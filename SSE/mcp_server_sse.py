from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
import subprocess
import json
import logging
import os
import time
from datetime import datetime
from urllib.parse import quote
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import asyncio

app = FastAPI()
logging.basicConfig(
    filename='logs/mcp_server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s:%(message)s'
)

def extract_payload(endpoint: str) -> str:
    if not endpoint:
        return ""
    try:
        parsed_url = endpoint.split('?')[1] if '?' in endpoint else endpoint
        params = parsed_url.split('&')
        for param in params:
            if '=' in param:
                value = param.split('=', 1)[1]
                if any(kw in value.lower() for kw in ['sleep', 'union', 'select', 'and', 'or', 'script', 'onerror', 'onload', 'alert', 'passwd', 'whoami']):
                    return value
    except IndexError:
        return ""
    return ""

def detect_injection_type(payload: str, error: str, template_id: str) -> str:
    if not payload:
        return "Unknown"
    payload = payload.lower()
    if 'sql-injection' in template_id.lower():
        if 'sleep' in payload or 'waitfor' in payload:
            return "Time-based"
        if 'union' in payload and 'select' in payload:
            return "Union-based"
        if any(kw in payload for kw in ['and', 'or']) and ('1=1' in payload or '1=2' in payload):
            return "Boolean-based"
        if error and any(kw in error.lower() for kw in ['sql syntax', 'mysql_fetch', 'sql error', 'query error', 'database error', 'mysql error']):
            return "Error-based"
    elif 'xss-detection' in template_id.lower():
        if any(kw in payload for kw in ['script', 'onerror', 'onload', 'alert', 'netsparker']):
            return "XSS"
    elif 'lfi-rce-detection' in template_id.lower():
        if any(kw in payload for kw in ['passwd', 'etc']):
            return "LFI"
        if any(kw in payload for kw in ['whoami', 'id', 'cmd']):
            return "RCE"
    return "Unknown"

def verify_lfi_rce(endpoint: str, payload: str) -> bool:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    try:
        encoded_endpoint = quote(endpoint, safe=':/?=&')
        response = session.get(encoded_endpoint, timeout=30).text
        if 'passwd' in payload.lower():
            return 'root:' in response or 'bin:' in response
        if 'whoami' in payload.lower():
            return any(user in response for user in ['root', 'www-data', 'nobody', 'user'])
        return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error verifying LFI/RCE for {endpoint}: {str(e)}")
        return False

def determine_severity(injection_type: str, verified: bool) -> str:
    if injection_type in ["Time-based", "RCE"] and verified:
        return "critical"
    elif injection_type in ["Union-based", "Boolean-based"] and verified:
        return "high"
    elif injection_type == "XSS" and verified:
        return "high"
    elif injection_type == "LFI" and verified:
        return "high"
    elif injection_type == "LFI" and not verified:
        return "medium"
    elif injection_type == "Error-based":
        return "medium"
    elif injection_type in ["Union-based", "Boolean-based", "XSS"] and not verified:
        return "low"
    else:
        return "low"

async def run_nuclei_scan_stream(url: str, templates: list, request_id: int):
    # Kiểm tra template tồn tại
    for template in templates:
        if not os.path.exists(template):
            error_msg = f"Template file not found: {template}"
            logging.error(error_msg)
            yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': error_msg}, 'id': request_id})}\n\n"
            return

    # Kiểm tra URL hợp lệ
    if not url.startswith(("http://", "https://")):
        error_msg = f"Invalid URL: {url}"
        logging.error(error_msg)
        yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': error_msg}, 'id': request_id})}\n\n"
        return

    # Kiểm tra Nuclei binary
    if not os.path.exists("/usr/local/bin/nuclei"):
        error_msg = "Nuclei binary not found in /usr/local/bin/nuclei"
        logging.error(error_msg)
        yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': error_msg}, 'id': request_id})}\n\n"
        return

    # Gửi thông báo bắt đầu quét qua SSE
    yield f"data: {json.dumps({'jsonrpc': '2.0', 'result': {'status': 'scanning'}, 'id': request_id})}\n\n"

    # Chạy Nuclei và stream kết quả
    start_time = time.time()
    cmd = ["nuclei", "-u", url, "-t", ",".join(templates), "-jsonl", "-silent", "-no-color", "-rate-limit", "10"]
    logging.info(f"Running Nuclei command: {' '.join(cmd)}")
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        vulnerabilities = []
        template_info = {}

        # Đọc từng dòng kết quả từ Nuclei
        while True:
            line = process.stdout.readline().strip()
            if not line and process.poll() is not None:
                break
            if line:
                try:
                    result = json.loads(line)
                    if not template_info:
                        template_info = result.get('info', {})
                    payload = extract_payload(result.get('matched-at', ''))
                    error = result.get('response', '').split('\n')[-1] if 'error in your SQL' in result.get('response', '') else None
                    template_id = result.get('template-id', 'unknown')
                    injection_type = detect_injection_type(payload, error, template_id)
                    lfi_rce_verified = verify_lfi_rce(result.get('matched-at', ''), payload) if injection_type in ["LFI", "RCE"] else None
                    verified = lfi_rce_verified
                    severity = determine_severity(injection_type, verified)
                    simplified_result = {
                        "matched-at": result.get('matched-at'),
                        "payload": payload,
                        "type": injection_type,
                        "verified": "Yes" if verified else "No",
                        "severity": severity,
                        "template-description": template_info.get('description', 'N/A'),
                        "template-reference": ', '.join(template_info.get('reference', ['N/A'])),
                        "template-author": ', '.join(template_info.get('author', ['N/A'])) if isinstance(template_info.get('author'), list) else template_info.get('author', 'N/A'),
                        "template-tags": ', '.join(template_info.get('tags', ['N/A']))
                    }
                    vulnerabilities.append(simplified_result)

                    # Gửi kết quả qua SSE
                    yield f"data: {json.dumps({'jsonrpc': '2.0', 'result': simplified_result, 'id': request_id})}\n\n"
                    await asyncio.sleep(0.1)  # Đợi để tránh chặn
                except json.JSONDecodeError as e:
                    logging.warning(f"Skipping invalid JSON line from Nuclei output: {line[:100]}")
                    continue

        # Xử lý lỗi từ stderr của Nuclei
        error = process.stderr.read()
        if process.returncode != 0:
            error_msg = error if error else "Nuclei exited with non-zero status"
            logging.error(f"Error scanning {url}: {error_msg}")
            yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': error_msg}, 'id': request_id})}\n\n"
            return

        if not vulnerabilities:
            error_msg = "No valid vulnerabilities found from Nuclei output"
            logging.error(error_msg)
            yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': error_msg}, 'id': request_id})}\n\n"
            return

        # Tính toán summary
        duration = time.time() - start_time
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Duration": round(duration, 2)}
        for vuln in vulnerabilities:
            if vuln["severity"] == "critical":
                summary["Critical"] += 1
            elif vuln["severity"] == "high":
                summary["High"] += 1
            elif vuln["severity"] == "medium":
                summary["Medium"] += 1
            elif vuln["severity"] == "low":
                summary["Low"] += 1

        # Gửi summary qua SSE
        yield f"data: {json.dumps({'jsonrpc': '2.0', 'result': {'status': 'completed', 'summary': summary, 'vulnerabilities': vulnerabilities}, 'id': request_id})}\n\n"

        logging.info(f"Scan completed for {url} at {datetime.now()}")

    except subprocess.TimeoutExpired:
        process.kill()
        error_msg = "Nuclei scan timed out after 150 seconds"
        logging.error(error_msg)
        yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': error_msg}, 'id': request_id})}\n\n"
    except subprocess.SubprocessError as e:
        error_msg = f"Failed to run Nuclei: {str(e)}"
        logging.error(error_msg)
        yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': error_msg}, 'id': request_id})}\n\n"
    except Exception as e:
        error_msg = str(e)
        logging.error(f"Exception during scan: {error_msg}")
        yield f"data: {json.dumps({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': error_msg}, 'id': request_id})}\n\n"

@app.post("/messages")
async def messages(request: Request):
    try:
        data = await request.json()
        logging.info(f"Received request data: {json.dumps(data)}")
    except Exception as e:
        logging.error(f"Failed to parse JSON request: {str(e)}")
        return {"jsonrpc": "2.0", "error": {"code": -32700, "message": f"Parse error: {str(e)}"}, "id": None}

    if "jsonrpc" not in data or data["jsonrpc"] != "2.0":
        error_msg = "Invalid Request: Must be a valid JSON-RPC 2.0 request"
        logging.error(error_msg)
        return {"jsonrpc": "2.0", "error": {"code": -32600, "message": error_msg}, "id": data.get("id")}

    request_id = data.get("id")
    if data.get("method") != "call_tool" or data["params"]["tool_name"] != "nuclei_scan":
        error_msg = "Invalid request: method must be 'call_tool' and tool_name must be 'nuclei_scan'"
        logging.error(error_msg)
        return {"jsonrpc": "2.0", "error": {"code": -32602, "message": error_msg}, "id": request_id}

    url = data["params"]["args"]["urls"][0]
    templates = data["params"]["args"]["template_paths"]
    logging.info(f"Processing nuclei_scan with URLs: {url}, Templates: {templates}")

    # Trả về StreamingResponse với SSE
    return StreamingResponse(run_nuclei_scan_stream(url, templates, request_id), media_type="text/event-stream")