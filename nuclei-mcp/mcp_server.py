import os
import sys
import json
import time
import yaml
import logging
import subprocess
from typing import List, Dict, Any
from urllib.parse import quote
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# Đảm bảo thư mục logs tồn tại
if not os.path.exists('logs'):
    os.makedirs('logs')

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s:%(name)s:%(message)s',
    handlers=[
        logging.FileHandler('logs/mcp_server.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def run_nuclei_scan(url: str, template_paths: List[str]) -> List[Dict[str, Any]]:
    abs_template_paths = [os.path.abspath(path) for path in template_paths]
    for path in abs_template_paths:
        if not os.path.exists(path):
            logger.error(f"Template file not found: {path}")
            return []
    logger.info(f"Current working directory: {os.getcwd()}")
    cmd = ["nuclei", "-u", url, "-t", ",".join(abs_template_paths), "-jsonl", "-silent", "-rate-limit", "10"]
    logger.info(f"Running Nuclei command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(f"Nuclei scan completed for {url}")
        scan_results = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    scan_results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing Nuclei output: {str(e)}", exc_info=True)
        return scan_results
    except subprocess.CalledProcessError as e:
        logger.error(f"Nuclei scan failed for {url}: {e.stderr}", exc_info=True)
        return []

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

def verify_time_based(endpoint: str) -> bool:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    try:
        encoded_endpoint = quote(endpoint, safe=':/?=&')
        base_url = quote(endpoint.split('=')[0] + "=1", safe=':/?=&')
        waitfor_endpoint = quote(endpoint.replace("SLEEP(10)", "WAITFOR DELAY '0:0:10'"), safe=':/?=&')
        start = time.time()
        base_response = session.get(base_url, timeout=30)
        base_duration = time.time() - start
        base_content = BeautifulSoup(base_response.text, 'html.parser').find('div', id='content').get_text() if BeautifulSoup(base_response.text, 'html.parser').find('div', id='content') else ""
        logger.info(f"Base request to {base_url} took {base_duration:.2f}s")
        start = time.time()
        sleep_response = session.get(encoded_endpoint, timeout=30)
        sleep_duration = time.time() - start
        sleep_content = BeautifulSoup(sleep_response.text, 'html.parser').find('div', id='content').get_text() if BeautifulSoup(sleep_response.text, 'html.parser').find('div', id='content') else ""
        logger.info(f"SLEEP request to {encoded_endpoint} took {sleep_duration:.2f}s")
        start = time.time()
        waitfor_response = session.get(waitfor_endpoint, timeout=30)
        waitfor_duration = time.time() - start
        waitfor_content = BeautifulSoup(waitfor_response.text, 'html.parser').find('div', id='content').get_text() if BeautifulSoup(waitfor_response.text, 'html.parser').find('div', id='content') else ""
        logger.info(f"WAITFOR request to {waitfor_endpoint} took {waitfor_duration:.2f}s")
        delay_verified = max(sleep_duration, waitfor_duration) - base_duration > 5
        content_verified = base_content != sleep_content or base_content != waitfor_content
        return delay_verified or (content_verified and (sleep_response.status_code == 200 or waitfor_response.status_code == 200))
    except requests.exceptions.RequestException as e:
        logger.error(f"Error verifying time-based injection for {endpoint}: {str(e)}", exc_info=True)
        return False

def verify_boolean_based(endpoint: str) -> bool:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    try:
        base_url = quote(endpoint.split('=')[0] + "=1", safe=':/?=&')
        encoded_endpoint = quote(endpoint, safe=':/?=&')
        base_response = session.get(base_url, timeout=30)
        injected_response = session.get(encoded_endpoint, timeout=30)

        # Kiểm tra mã trạng thái
        if base_response.status_code != injected_response.status_code:
            return True

        # So sánh nội dung phản hồi
        base_text = base_response.text
        injected_text = injected_response.text
        base_soup = BeautifulSoup(base_text, 'html.parser')
        injected_soup = BeautifulSoup(injected_text, 'html.parser')

        # So sánh nội dung cụ thể
        base_content = base_soup.find('div', id='content').get_text() if base_soup.find('div', id='content') else base_text
        injected_content = injected_soup.find('div', id='content').get_text() if injected_soup.find('div', id='content') else injected_text
        content_changed = base_content != injected_content

        # So sánh số lượng phần tử HTML
        base_elements = len(base_soup.find_all(['tr', 'li', 'div', 'p', 'span', 'a']))
        injected_elements = len(injected_soup.find_all(['tr', 'li', 'div', 'p', 'span', 'a']))
        elements_changed = abs(base_elements - injected_elements) > 1

        # So sánh độ dài nội dung
        length_diff = abs(len(base_text) - len(injected_text)) > 10

        return content_changed or elements_changed or length_diff
    except requests.exceptions.RequestException as e:
        logger.error(f"Error verifying boolean-based injection for {endpoint}: {str(e)}", exc_info=True)
        return False

def verify_xss(endpoint: str, payload: str) -> bool:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    try:
        encoded_endpoint = quote(endpoint, safe=':/?=&')
        response = session.get(encoded_endpoint, timeout=30).text
        soup = BeautifulSoup(response, 'html.parser')

        # Kiểm tra sự hiện diện của payload
        payload_present = payload.lower() in response.lower()

        # Kiểm tra xem payload có được thực thi hay không (không bị thoát ký tự)
        script_tags = soup.find_all('script')
        for script in script_tags:
            if payload.lower() in str(script).lower() and '<!--' not in str(script) and '<![CDATA[' not in str(script):
                return True

        # Kiểm tra các thuộc tính nguy hiểm
        dangerous_attrs = ['onerror', 'onload', 'onmouseover', 'onclick']
        for tag in soup.find_all(True):
            for attr in dangerous_attrs:
                if tag.has_attr(attr) and payload.lower() in tag[attr].lower():
                    return True

        # Kiểm tra xem payload có bị thoát ký tự không (ví dụ: <script> thành <script>)
        escaped_payload = payload.replace('<', '<').replace('>', '>').lower()
        if escaped_payload in response.lower():
            return False  # Payload bị thoát ký tự, không thực thi được

        return payload_present and '<![CDATA[' not in response and '<!--' not in response
    except requests.exceptions.RequestException as e:
        logger.error(f"Error verifying XSS for {endpoint}: {str(e)}", exc_info=True)
        return False

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
        logger.error(f"Error verifying LFI/RCE for {endpoint}: {str(e)}", exc_info=True)
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

def log_text_result(url: str, result: Dict[str, Any]):
    with open('logs/results.log', 'a', encoding='utf-8') as f:
        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {url}\n")
        f.write(f"Template: {result['template-id']}\n")
        if 'vulnerabilities' in result and result['vulnerabilities']:
            f.write("Vulnerabilities Found:\n")
            for vuln in result['vulnerabilities']:
                f.write(f"- Endpoint: {vuln['matched-at']}\n")
                f.write(f"  Payload: {vuln['payload']}\n")
                f.write(f"  Type: {vuln['type']}\n")
                if vuln.get('error'):
                    f.write(f"  Error: \t{vuln['error']}\n")
                if vuln['type'] == 'Time-based' and vuln.get('time-based-verified') is not None:
                    f.write(f"  Time-based Verified: {'Yes' if vuln['time-based-verified'] else 'No'}\n")
                if vuln['type'] == 'Boolean-based' and vuln.get('boolean-based-verified') is not None:
                    f.write(f"  Boolean-based Verified: {'Yes' if vuln['boolean-based-verified'] else 'No'}\n")
                if vuln['type'] in ['XSS', 'LFI', 'RCE'] and vuln.get('verified') is not None:
                    f.write(f"  Verified: {'Yes' if vuln['verified'] else 'No'}\n")
                f.write(f"  Severity: {vuln['severity']}\n")
                f.write(f"  Description: {vuln['template-description']}\n")
                f.write(f"  Reference: {vuln['template-reference']}\n")
                f.write(f"  Author: {vuln['template-author']}\n")
                f.write(f"  Tags: {vuln['template-tags']}\n")
        else:
            f.write("No vulnerabilities found.\n")
        f.write("\n")

def nuclei_scan(urls: List[str], template_paths: List[str]) -> dict:
    logger.info(f"Starting nuclei_scan with URLs: {urls}, Templates: {template_paths}")
    results = []
    if os.path.exists('logs/scan_results.json'):
        os.remove('logs/scan_results.json')
    for url in urls:
        scan_results = run_nuclei_scan(url, template_paths)
        result_entry = {
            "url": url,
            "template-id": os.path.basename(template_paths[0]),
            "vulnerabilities": []
        }
        template_info = {}
        if scan_results:
            template_info = scan_results[0].get('info', {})
        for result in scan_results:
            payload = extract_payload(result.get('matched-at', ''))
            error = result.get('response', '').split('\n')[-1] if 'error in your SQL' in result.get('response', '') else None
            template_id = result.get('template-id', 'unknown')
            injection_type = detect_injection_type(payload, error, template_id)
            time_based_verified = verify_time_based(result.get('matched-at', '')) if injection_type == "Time-based" else None
            boolean_based_verified = verify_boolean_based(result.get('matched-at', '')) if injection_type == "Boolean-based" else None
            xss_verified = verify_xss(result.get('matched-at', ''), payload) if injection_type == "XSS" else None
            lfi_rce_verified = verify_lfi_rce(result.get('matched-at', ''), payload) if injection_type in ["LFI", "RCE"] else None
            verified = time_based_verified or boolean_based_verified or xss_verified or lfi_rce_verified
            severity = determine_severity(injection_type, verified)
            simplified_result = {
                'template-id': template_id,
                'matched-at': result.get('matched-at'),
                'severity': severity,
                'error': error,
                'payload': payload,
                'type': injection_type,
                'time-based-verified': time_based_verified,
                'boolean-based-verified': boolean_based_verified,
                'verified': verified,
                'template-description': template_info.get('description', 'N/A'),
                'template-reference': ', '.join(template_info.get('reference', ['N/A'])),
                'template-author': ', '.join(template_info.get('author', ['N/A'])) if isinstance(template_info.get('author'), list) else template_info.get('author', 'N/A'),
                'template-tags': ', '.join(template_info.get('tags', ['N/A']))
            }
            result_entry['vulnerabilities'].append(simplified_result)
            with open('logs/scan_results.json', 'a', encoding='utf-8') as f:
                json.dump(simplified_result, f, ensure_ascii=False)
                f.write('\n')
        results.append(result_entry)
        log_text_result(url, result_entry)
    return results

def main():
    for line in sys.stdin:
        try:
            # Nhận yêu cầu JSON-RPC
            request = json.loads(line.strip())
            if not isinstance(request, dict) or "jsonrpc" not in request or request["jsonrpc"] != "2.0":
                response = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: Must be a valid JSON-RPC 2.0 request"
                    },
                    "id": None
                }
                print(json.dumps(response))
                sys.stdout.flush()
                continue

            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            # Xử lý các phương thức
            if method == "list_tools":
                response = {
                    "jsonrpc": "2.0",
                    "result": {"tools": ["nuclei_scan"]},
                    "id": request_id
                }
                print(json.dumps(response))
                sys.stdout.flush()
            elif method == "call_tool":
                tool_name = params.get("tool_name")
                if tool_name != "nuclei_scan":
                    response = {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32602,
                            "message": "Invalid Parameter: Unsupported tool name"
                        },
                        "id": request_id
                    }
                    print(json.dumps(response))
                    sys.stdout.flush()
                    continue

                args = params.get("args", {})
                urls = args.get("urls", [])
                template_paths = args.get("template_paths", [])
                if not urls or not template_paths:
                    response = {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32602,
                            "message": "Invalid Parameter: urls and template_paths are required"
                        },
                        "id": request_id
                    }
                    print(json.dumps(response))
                    sys.stdout.flush()
                    continue

                result = nuclei_scan(urls, template_paths)
                response = {
                    "jsonrpc": "2.0",
                    "result": result,
                    "id": request_id
                }
                print(json.dumps(response))
                sys.stdout.flush()
            else:
                response = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": "Method not found"
                    },
                    "id": request_id
                }
                print(json.dumps(response))
                sys.stdout.flush()

        except json.JSONDecodeError as e:
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {str(e)}"
                },
                "id": None
            }
            print(json.dumps(response))
            sys.stdout.flush()
        except Exception as e:
            logger.error(f"Unexpected error in main: {str(e)}", exc_info=True)
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Server error: {str(e)}"
                },
                "id": None
            }
            print(json.dumps(response))
            sys.stdout.flush()

if __name__ == "__main__":
    main()