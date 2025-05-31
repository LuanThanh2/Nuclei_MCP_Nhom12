from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv
import logging
import re
import time
import aiohttp
import asyncio

# Cấu hình logging
logging.basicConfig(
    filename='logs/web_client.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s:%(message)s'
)

load_dotenv()
app = FastAPI()
templates = Jinja2Templates(directory="templates")

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions"
SSE_PORT = int(os.getenv("SSE_PORT", 8001))
SSE_HOST = os.getenv("SSE_HOST", "mcp-server")

# Biến toàn cục để lưu kết quả quét tạm thời
current_scan_results = []
current_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Duration": 0}
current_analysis = ""
current_url = ""
current_template = ""
current_start_time = None

async def sse_proxy():
    global current_scan_results, current_summary, current_analysis
    current_scan_results = []
    current_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Duration": 0}
    current_analysis = ""

    async with aiohttp.ClientSession() as session:
        try:
            # Lấy dữ liệu quét từ biến toàn cục (được lưu khi gọi /messages)
            data = {
                "jsonrpc": "2.0",
                "method": "call_tool",
                "params": {
                    "tool_name": "nuclei_scan",
                    "args": {
                        "urls": [current_url],
                        "template_paths": [f"scanner/templates/{current_template}"]
                    }
                },
                "id": 1
            }
            async with session.post(f"http://{SSE_HOST}:{SSE_PORT}/messages", json=data, timeout=180) as response:
                if response.status != 200:
                    error_msg = f"Failed to connect to MCP Server: {response.status}"
                    logging.error(error_msg)
                    yield f"data: {json.dumps({'status': 'error', 'message': error_msg})}\n\n"
                    return

                async for line in response.content:
                    if line:
                        line = line.decode('utf-8').strip()
                        if line.startswith("data:"):
                            data = line[5:].strip()
                            try:
                                event = json.loads(data)
                                if "jsonrpc" in event and event["jsonrpc"] == "2.0":
                                    if "error" in event:
                                        yield f"data: {json.dumps({'status': 'error', 'message': event['error']['message']})}\n\n"
                                        current_analysis = event['error']['message']
                                        return
                                    result = event.get("result", {})
                                    if result.get("status") == "scanning":
                                        yield f"data: {json.dumps({'status': 'scanning'})}\n\n"
                                    elif result.get("status") == "completed":
                                        current_summary = result.get("summary", current_summary)
                                        current_scan_results = result.get("vulnerabilities", current_scan_results)
                                        yield f"data: {json.dumps({'status': 'completed', 'summary': current_summary, 'vulnerabilities': current_scan_results})}\n\n"
                                    else:
                                        current_scan_results.append(result)
                                        severity = result.get("severity", "low").lower()
                                        if severity == "critical":
                                            current_summary["Critical"] += 1
                                        elif severity == "high":
                                            current_summary["High"] += 1
                                        elif severity == "medium":
                                            current_summary["Medium"] += 1
                                        else:
                                            current_summary["Low"] += 1
                                        yield f"data: {json.dumps({'status': 'progress', 'vulnerability': result})}\n\n"
                            except json.JSONDecodeError:
                                logging.warning(f"Skipping invalid JSON line in SSE: {data[:100]}")
                                continue
        except aiohttp.ClientError as e:
            error_msg = f"Error during SSE streaming from MCP Server: {str(e)}"
            logging.error(error_msg)
            current_analysis = error_msg
            yield f"data: {json.dumps({'status': 'error', 'message': error_msg})}\n\n"

@app.get("/sse")
async def sse_endpoint():
    return StreamingResponse(sse_proxy(), media_type="text/event-stream")

@app.post("/messages")
async def messages(request: Request):
    try:
        data = await request.json()
        logging.info(f"Received /messages request: {json.dumps(data)}")
    except Exception as e:
        logging.error(f"Failed to parse JSON request in /messages: {str(e)}")
        return {"status": "error", "message": f"Invalid JSON request: {str(e)}"}

    if data.get("method") != "call_tool" or data["params"]["tool_name"] != "nuclei_scan":
        error_msg = "Invalid request: method must be 'call_tool' and tool_name must be 'nuclei_scan'"
        logging.error(error_msg)
        return {"status": "error", "message": error_msg}

    global current_url, current_template, current_start_time
    current_url = data["params"]["args"]["urls"][0]
    current_template = data["params"]["args"]["template_paths"][0].split('/')[-1]
    current_start_time = datetime.now()
    logging.info(f"Initialized scan for URL: {current_url}, Template: {current_template}")
    return {"status": "received"}

@app.get("/")
async def index(request: Request):
    try:
        templates_list = os.listdir("scanner/templates")
        logging.info(f"Loaded templates list: {templates_list}")
        return templates.TemplateResponse("index.html", {"request": request, "templates": templates_list})
    except FileNotFoundError as e:
        logging.error(f"Failed to load templates directory: {str(e)}")
        return templates.TemplateResponse("index.html", {"request": request, "templates": [], "error_message": "Templates directory not found"})
    except Exception as e:
        logging.error(f"Unexpected error in / endpoint: {str(e)}")
        return templates.TemplateResponse("index.html", {"request": request, "templates": [], "error_message": str(e)})

@app.get("/results", response_class=HTMLResponse)
async def results(request: Request):
    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "results": current_scan_results,
            "summary": current_summary,
            "duration": current_summary["Duration"],
            "analysis": current_analysis,
            "error_message": "No vulnerabilities found. Please run a scan first." if not current_scan_results and not current_analysis else None
        }
    )

@app.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    scan_history = []
    if os.path.exists('logs/scan_history.json'):
        try:
            with open('logs/scan_history.json', 'r', encoding='utf-8') as f:
                scan_history = json.load(f)
        except Exception as e:
            scan_history = []
            logging.error(f"Error reading scan_history.json: {str(e)}")
    return templates.TemplateResponse("history.html", {"request": request, "scan_history": scan_history})

@app.get("/history/{results_file}", response_class=HTMLResponse)
async def view_history_results(request: Request, results_file: str):
    scan_results = []
    results_path = f"logs/{results_file}"
    if os.path.exists(results_path):
        try:
            with open(results_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            scan_results.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            logging.warning(f"Skipping invalid JSON line in {results_path}: {line[:100]}")
                            continue
        except Exception as e:
            scan_results = []
            logging.error(f"Error reading {results_path}: {str(e)}")

    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Duration": 0}
    for result in scan_results:
        severity = result.get('severity', 'low').lower()
        if severity == "critical":
            summary["Critical"] += 1
        elif severity == "high":
            summary["High"] += 1
        elif severity == "medium":
            summary["Medium"] += 1
        else:
            summary["Low"] += 1

    scan_history = []
    duration = 0
    analysis = "No analysis available."
    if os.path.exists('logs/scan_history.json'):
        try:
            with open('logs/scan_history.json', 'r', encoding='utf-8') as f:
                scan_history = json.load(f)
            for entry in scan_history:
                if entry.get('results_file') == results_file:
                    duration = entry.get('duration', 0)
                    summary["Duration"] = duration
                    analysis = entry.get('analysis', "No analysis available.")
                    break
        except Exception as e:
            logging.error(f"Error reading scan_history.json: {str(e)}")

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "results": scan_results,
            "summary": summary,
            "duration": duration,
            "analysis": analysis,
            "error_message": "No vulnerabilities found in this scan session." if not scan_results else None
        }
    )

@app.post("/scan")
async def scan(request: Request):
    def render_error_template(request, error_message):
        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "error_message": error_message,
                "results": [],
                "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Duration": 0},
                "duration": 0,
                "analysis": ""
            }
        )

    try:
        form = await request.form()
        scan_type = form.get("scan_type")
        if scan_type is None:
            error_message = "Scan type is missing in the form data"
            logging.error(error_message)
            return render_error_template(request, error_message)
        scan_type = scan_type.lower()
        start_time = datetime.now()
        logging.info(f"Received /scan request with scan_type: {scan_type}")
    except Exception as e:
        logging.error(f"Failed to parse form data in /scan: {str(e)}")
        return render_error_template(request, f"Failed to parse form data: {str(e)}")

    global current_url, current_template, current_start_time, current_scan_results, current_summary, current_analysis
    current_url = form.get("url", "")
    current_template = form.get("template", "")
    current_start_time = start_time
    current_scan_results = []  # Reset kết quả quét
    current_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Duration": 0}  # Reset summary
    current_analysis = ""  # Reset phân tích

    if scan_type == "manual":
        url = form.get("url", "").strip()
        template = form.get("template", "").strip()
        if not url or not url.startswith(("http://", "https://")):
            error_message = "Invalid URL: URL must start with http:// or https://"
            logging.error(error_message)
            await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": template, "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
            return render_error_template(request, error_message)
        if not template or not template.endswith(".yaml"):
            error_message = "Invalid template: Template must be a .yaml file"
            logging.error(error_message)
            await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": template, "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
            return render_error_template(request, error_message)
        url = re.sub(r'[^a-zA-Z0-9:/?=&._-]', '', url)
        template = re.sub(r'[^a-zA-Z0-9_\-\.]', '', template)
        template_path = f"scanner/templates/{template}"
        if not os.path.exists(template_path):
            error_message = f"Template file not found: {template_path}"
            logging.error(error_message)
            await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": template, "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
            return render_error_template(request, error_message)

        data = {
            "jsonrpc": "2.0",
            "method": "call_tool",
            "params": {
                "tool_name": "nuclei_scan",
                "args": {
                    "urls": [url],
                    "template_paths": [template_path]
                }
            },
            "id": 1
        }
        try:
            # Gửi yêu cầu tới mcp_server_sse.py
            async with aiohttp.ClientSession() as session:
                async with session.post(f"http://{SSE_HOST}:{SSE_PORT}/messages", json=data, timeout=5) as response:
                    if response.status != 200:
                        error_message = f"Failed to start scan: {response.status}"
                        logging.error(error_message)
                        await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": template, "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
                        return render_error_template(request, error_message)
            logging.info(f"Sent scan request to mcp-server for URL: {url}")
            # Hiển thị giao diện chờ kết quả từ SSE
            return templates.TemplateResponse("results.html", {
                "request": request,
                "results": [],
                "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Duration": 0},
                "duration": 0,
                "analysis": "Scan started. Results will be streamed below."
            })
        except aiohttp.ClientError as e:
            error_message = f"Failed to communicate with MCP Server: {str(e)}"
            logging.error(error_message)
            await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": template, "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
            return render_error_template(request, error_message)
    elif scan_type == "deepseek":
        deepseek_input = form.get("deepseek_input", "").strip()
        if not deepseek_input:
            error_message = "DeepSeek command cannot be empty"
            logging.error(error_message)
            await save_to_history({"timestamp": start_time.isoformat(), "url": "", "template": "", "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
            return render_error_template(request, error_message)

        # Trích xuất URL từ deepseek_input (giả sử cú pháp là "Scan <URL> for <something>")
        url = ""
        try:
            # Tìm URL trong deepseek_input bằng regex
            url_match = re.search(r'(https?://[^\s]+)', deepseek_input)
            if url_match:
                url = url_match.group(0)
            else:
                error_message = "No valid URL found in DeepSeek command. Example: Scan http://demo.testfire.net for XSS"
                logging.error(error_message)
                await save_to_history({"timestamp": start_time.isoformat(), "url": "", "template": "", "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
                return render_error_template(request, error_message)

            # Kiểm tra URL hợp lệ
            if not url.startswith(("http://", "https://")):
                error_message = f"Invalid URL in DeepSeek command: {url}. URL must start with http:// or https://"
                logging.error(error_message)
                await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": "", "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
                return render_error_template(request, error_message)
        except Exception as e:
            error_message = f"Error parsing DeepSeek command: {str(e)}"
            logging.error(error_message)
            await save_to_history({"timestamp": start_time.isoformat(), "url": "", "template": "", "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
            return render_error_template(request, error_message)

        # Lấy danh sách tất cả các template từ thư mục scanner/templates/
        try:
            templates_list = os.listdir("scanner/templates")
            # Lọc chỉ lấy các file có đuôi .yaml
            templates_list = [t for t in templates_list if t.endswith(".yaml")]
            if not templates_list:
                error_message = "No templates found in scanner/templates/ directory"
                logging.error(error_message)
                await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": "", "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
                return render_error_template(request, error_message)
        except FileNotFoundError as e:
            error_message = f"Failed to load templates directory: {str(e)}"
            logging.error(error_message)
            await save_to_history({"timestamp": start_time.isoformat(), "url": url, "template": "", "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
            return render_error_template(request, error_message)

        # Nếu URL hợp lệ, tiếp tục xử lý quét với từng template
        current_url = url
        current_start_time = start_time
        all_templates = [f"scanner/templates/{template}" for template in templates_list]
        templates_used = ", ".join(templates_list)

        async with aiohttp.ClientSession() as session:
            for template_path in all_templates:
                template_name = template_path.split('/')[-1]
                logging.info(f"Scanning URL {url} with template: {template_name}")

                # Gửi yêu cầu tới mcp_server_sse.py cho từng template
                data = {
                    "jsonrpc": "2.0",
                    "method": "call_tool",
                    "params": {
                        "tool_name": "nuclei_scan",
                        "args": {
                            "urls": [url],
                            "template_paths": [template_path]
                        }
                    },
                    "id": 1
                }
                try:
                    async with session.post(f"http://{SSE_HOST}:{SSE_PORT}/messages", json=data, timeout=180) as response:
                        if response.status != 200:
                            error_message = f"Failed to start scan with template {template_name}: {response.status}"
                            logging.error(error_message)
                            current_analysis = error_message
                            continue

                        async for line in response.content:
                            if line:
                                line = line.decode('utf-8').strip()
                                if line.startswith("data:"):
                                    data = line[5:].strip()
                                    try:
                                        event = json.loads(data)
                                        if "jsonrpc" in event and event["jsonrpc"] == "2.0":
                                            if "error" in event:
                                                current_analysis = event['error']['message']
                                                logging.error(f"Error with template {template_name}: {current_analysis}")
                                                break
                                            result = event.get("result", {})
                                            if result.get("status") == "scanning":
                                                continue
                                            elif result.get("status") == "completed":
                                                current_summary = result.get("summary", current_summary)
                                                current_scan_results.extend(result.get("vulnerabilities", []))
                                            else:
                                                current_scan_results.append(result)
                                                severity = result.get("severity", "low").lower()
                                                if severity == "critical":
                                                    current_summary["Critical"] += 1
                                                elif severity == "high":
                                                    current_summary["High"] += 1
                                                elif severity == "medium":
                                                    current_summary["Medium"] += 1
                                                else:
                                                    current_summary["Low"] += 1
                                    except json.JSONDecodeError:
                                        logging.warning(f"Skipping invalid JSON line in SSE: {data[:100]}")
                                        continue
                except aiohttp.ClientError as e:
                    error_message = f"Failed to communicate with MCP Server for template {template_name}: {str(e)}"
                    logging.error(error_message)
                    current_analysis = error_message
                    continue

        # Cập nhật thời gian quét
        end_time = datetime.now()
        current_summary["Duration"] = (end_time - start_time).total_seconds()

        # Lưu lịch sử quét
        await save_to_history({
            "timestamp": start_time.isoformat(),
            "url": url,
            "template": templates_used,
            "summary": current_summary,
            "duration": current_summary["Duration"],
            "analysis": current_analysis if current_analysis else "Scan completed successfully."
        }, start_time)

        # Hiển thị kết quả
        return templates.TemplateResponse("results.html", {
            "request": request,
            "results": current_scan_results,
            "summary": current_summary,
            "duration": current_summary["Duration"],
            "analysis": f"Scan completed using templates: {templates_used}.",
            "error_message": None if current_scan_results else "No vulnerabilities found."
        })
    else:
        error_message = f"Invalid scan type: {scan_type}. Expected 'manual' or 'deepseek'"
        logging.error(error_message)
        await save_to_history({"timestamp": start_time.isoformat(), "url": "", "template": "", "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "duration": 0, "analysis": error_message}, start_time)
        return render_error_template(request, error_message)

async def save_to_history(history_entry, start_time):
    try:
        end_time = datetime.now()
        history_entry["duration"] = (end_time - start_time).total_seconds()
        if not os.path.exists("logs"):
            os.makedirs("logs")
            logging.info("Created logs directory for saving history")
        if not os.path.exists("logs/scan_history.json"):
            with open("logs/scan_history.json", "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False, indent=2)
            logging.info("Initialized empty scan history file")
        try:
            with open("logs/scan_history.json", "r", encoding="utf-8") as f:
                history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.warning(f"Error loading scan history, initializing empty history: {str(e)}")
            history = []

        # Lưu kết quả quét vào file riêng
        results_file = f"scan_results_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(f"logs/{results_file}", "w", encoding="utf-8") as f:
            for result in current_scan_results:
                json.dump(result, f, ensure_ascii=False)
                f.write('\n')
        history_entry["results_file"] = results_file
        history_entry["summary"] = current_summary
        history_entry["analysis"] = current_analysis

        history.append(history_entry)
        with open("logs/scan_history.json", "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
        logging.info(f"Saved scan history entry at {history_entry['timestamp']}")
    except Exception as e:
        logging.error(f"Failed to save scan history: {str(e)}")