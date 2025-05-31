import os
import sys
import json
import subprocess
import logging
import requests
from dotenv import load_dotenv
import re

# Tải API Key từ file .env
load_dotenv()
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
if not DEEPSEEK_API_KEY:
    raise Exception("DEEPSEEK_API_KEY not found in .env file")

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s:%(name)s:%(message)s',
    handlers=[
        logging.FileHandler('logs/ai_agent_client.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_available_templates():
    template_dir = os.path.join("scanner", "templates")
    templates = [
        os.path.join(template_dir, f) for f in os.listdir(template_dir)
        if f.endswith('.yaml') or f.endswith('.yml')
    ]
    return templates

def fix_json_content(content):
    try:
        content = content.replace('id:1', '"id": 1')
        content = content.strip()
        if content.endswith('},'):
            content = content[:-1]
        if content.endswith('}'):
            open_braces = content.count('{')
            close_braces = content.count('}')
            if close_braces > open_braces:
                content = content[:content.rfind('}')]
        return content
    except Exception as e:
        logger.error(f"Error fixing JSON content: {str(e)}")
        return content

def extract_json_from_text(content):
    """Trích xuất JSON từ văn bản nếu có."""
    try:
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            return json.loads(json_str)
        return None
    except Exception as e:
        logger.error(f"Error extracting JSON from text: {str(e)}")
        return None

def call_deepseek(command, context=None, retry=False):
    context_value = context if context else ""
    prompt = f"""
You are an AI assistant helping with vulnerability scanning using Nuclei MCP. The user has provided the following command: "{command}". Your task is to:

1. Parse the command to extract the target URL and the type of vulnerability to scan for (e.g., XSS, SQL Injection, LFI, RCE).
2. If no vulnerability type is specified, perform a general scan using templates for XSS, SQL Injection, LFI/RCE, CSRF, IDOR, SSRF, BAC, and Sensitive Data Exposure.
3. If the command is invalid or cannot be understood, return a JSON error message in the format:
   {{ "error": "Invalid command. Please provide a command in the format 'Scan [URL] for [Vulnerability]'." }}
4. If the vulnerability type is specified but not supported (i.e., not in the list below), return a JSON error message in the format:
   {{ "error": "Unsupported vulnerability type. Supported types are: XSS, SQL Injection, LFI, RCE, CVE-2019-9641, CSRF, IDOR, SSRF, BAC, Sensitive Data Exposure." }}
5. Based on the vulnerability type, select the appropriate template(s) from the following list:
   - XSS: scanner/templates/xss-detection.yaml
   - SQL Injection: scanner/templates/sql_injection_advanced.yaml
   - LFI or RCE: scanner/templates/lfi-rce-detection.yaml
   - CVE-2019-9641: scanner/templates/cve-2019-9641.yaml
   - CSRF: scanner/templates/csrf-detection.yaml
   - IDOR: scanner/templates/idor-detection.yaml
   - SSRF: scanner/templates/ssrf-detection.yaml
   - BAC: scanner/templates/bac-detection.yaml
   - Sensitive Data Exposure: scanner/templates/sensitive-data-exposure.yaml
6. Generate a JSON-RPC request in the following format. Ensure the JSON is valid and properly formatted with double quotes around keys and values:
   {{ "request": {{ "jsonrpc": "2.0", "method": "call_tool", "params": {{ "tool_name": "nuclei_scan", "args": {{ "urls": ["<target_url>"], "template_paths": ["<selected_template>"] }} }}, "id": 1 }} }}
7. If the command requests analysis of scan results, analyze the provided results and return a JSON response in the format:
   {{ "text": "Your analysis and recommendations here." }}

### Instructions:
- Your response MUST be a valid JSON object (e.g., {{ "request": {{...}} }} or {{ "error": "message" }}).
- Do NOT include any additional text, explanations, or comments outside the JSON object.
- Do NOT include markdown formatting (e.g., ```json) in your response.
- Only return the JSON object itself.

### Examples:
- Command: "Scan http://demo.testfire.net for XSS"
  Output:
  {{ "request": {{ "jsonrpc": "2.0", "method": "call_tool", "params": {{ "tool_name": "nuclei_scan", "args": {{ "urls": ["http://demo.testfire.net"], "template_paths": ["scanner/templates/xss-detection.yaml"] }} }}, "id": 1 }} }}

- Command: "Scan http://demo.testfire.net"
  Output:
  {{ "request": {{ "jsonrpc": "2.0", "method": "call_tool", "params": {{ "tool_name": "nuclei_scan", "args": {{ "urls": ["http://demo.testfire.net"], "template_paths": [ "scanner/templates/xss-detection.yaml", "scanner/templates/sql_injection_advanced.yaml", "scanner/templates/lfi-rce-detection.yaml", "scanner/templates/csrf-detection.yaml", "scanner/templates/idor-detection.yaml", "scanner/templates/ssrf-detection.yaml", "scanner/templates/bac-detection.yaml", "scanner/templates/sensitive-data-exposure.yaml" ] }} }}, "id": 1 }} }}

- Command: "Scan http://demo.testfire.net for XXE"
  Output:
  {{ "error": "Unsupported vulnerability type. Supported types are: XSS, SQL Injection, LFI, RCE, CVE-2019-9641, CSRF, IDOR, SSRF, BAC, Sensitive Data Exposure." }}

- Command: "Invalid command"
  Output:
  {{ "error": "Invalid command. Please provide a command in the format 'Scan [URL] for [Vulnerability]'." }}

{context_value}
"""
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "deepseek-coder",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1000,
        "temperature": 0.7
    }
    try:
        response = requests.post("https://api.deepseek.com/v1/chat/completions", headers=headers, json=data)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        try:
            result = json.loads(content)
            return result
        except json.JSONDecodeError:
            result = extract_json_from_text(content)
            if result:
                return result
            fixed_content = fix_json_content(content)
            try:
                result = json.loads(fixed_content)
                return result
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON after fixing: {fixed_content}")
                if not retry:
                    new_prompt = f"The previous response you generated was invalid JSON: {content}. Please ensure your response is a valid JSON object following the formats specified above (e.g., {{ \"request\": {{...}} }} or {{ \"error\": \"message\" }}), and do not include any additional text or markdown formatting."
                    return call_deepseek(new_prompt, context, retry=True)
                else:
                    return {"error": f"Unable to process DeepSeek response: {content}"}
    except Exception as e:
        logger.error(f"Error calling DeepSeek: {str(e)}")
        raise Exception(f"Error calling DeepSeek: {str(e)}")

def call_mcp_server(request):
    process = subprocess.Popen(
        ["python", "mcp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()

    while True:
        line = process.stdout.readline().strip()
        if not line:
            break
        try:
            response = json.loads(line)
            if "jsonrpc" in response and response["jsonrpc"] == "2.0":
                if "error" in response:
                    raise Exception(f"MCP Server error: {response['error']['message']} (code: {response['error']['code']})")
                if "result" in response:
                    return response["result"]
            else:
                logger.warning(f"Invalid JSON-RPC response: {line}")
        except json.JSONDecodeError:
            logger.warning(f"Non-JSON output from mcp_server.py: {line}")
            continue

    stderr_output = process.stderr.read()
    if stderr_output:
        raise Exception(f"Error from mcp_server.py: {stderr_output}")
    raise Exception("No valid JSON-RPC response received from mcp_server.py")

def main():
    command = input("Enter command (e.g., Scan http://demo.testfire.net for XSS): ").strip()

    try:
        deepseek_response = call_deepseek(command)
        if "error" in deepseek_response:
            print(f"Error: {deepseek_response['error']}")
            return
        if "request" in deepseek_response:
            request = deepseek_response["request"]
            logger.info(f"Request from DeepSeek: {json.dumps(request, indent=2)}")

            result = call_mcp_server(request)

            if not result or not result[0].get("url"):
                print(f"Error: Target {request['params']['args']['urls'][0]} did not respond. Please check the URL and try again.")
                return

            # Ghi kết quả quét vào logs/scan_results.json
            scan_results = []
            if result and result[0].get("vulnerabilities"):
                with open('logs/scan_results.json', 'w', encoding='utf-8') as f:
                    for entry in result:
                        if entry.get("vulnerabilities"):
                            for vuln in entry["vulnerabilities"]:
                                json.dump(vuln, f, ensure_ascii=False)
                                f.write('\n')
                                scan_results.append(vuln)

            # Phân tích kết quả quét bằng DeepSeek
            analysis_context = f"Scan results: {json.dumps(result, indent=2)}"
            analysis_response = call_deepseek("Analyze the scan results and provide a summary with recommendations", context=analysis_context)

            print("Analysis from DeepSeek:")
            print(analysis_response.get("text", "No analysis provided"))

            if result:
                print("\nScan Results:")
                for entry in result:
                    print(f"- Target: {entry['url']}")
                    print(f"  Template: {entry['template-id']}")
                    if entry['vulnerabilities']:
                        print("  Vulnerabilities Found:")
                        for vuln in entry['vulnerabilities']:
                            print(f"    - Endpoint: {vuln['matched-at']}")
                            print(f"      Payload: {vuln['payload']}")
                            print(f"      Type: {vuln['type']}")
                            print(f"      Severity: {vuln['severity']}")
                            print(f"      Description: {vuln['template-description']}")
                    else:
                        print("  No vulnerabilities found.")
                    print("Check logs/results.log for details.")
            else:
                print("No vulnerabilities found.")
        else:
            print("DeepSeek Response:")
            print(deepseek_response.get("text", "No response from DeepSeek"))
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()