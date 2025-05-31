import os
import sys
import json
import subprocess
import logging

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s:%(name)s:%(message)s',
    handlers=[
        logging.FileHandler('logs/agent_call_mcp.log', encoding='utf-8'),
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

def call_mcp_server(request):
    # Khởi tạo tiến trình mcp_server.py
    process = subprocess.Popen(
        ["python", "mcp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Gửi yêu cầu theo chuẩn JSON-RPC
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()

    # Đọc các dòng từ stdout cho đến khi tìm được JSON hợp lệ
    while True:
        line = process.stdout.readline().strip()
        if not line:
            break
        try:
            response = json.loads(line)
            # Kiểm tra xem phản hồi có đúng chuẩn JSON-RPC không
            if "jsonrpc" in response and response["jsonrpc"] == "2.0":
                if "error" in response:
                    raise Exception(f"MCP Server error: {response['error']['message']} (code: {response['error']['code']})")
                if "result" in response:
                    return response["result"]
            else:
                logger.warning(f"Invalid JSON-RPC response: {line}")
        except json.JSONDecodeError:
            # Bỏ qua các dòng không phải JSON
            logger.warning(f"Non-JSON output from mcp_server.py: {line}")
            continue

    # Nếu không tìm thấy JSON hợp lệ, kiểm tra stderr
    stderr_output = process.stderr.read()
    if stderr_output:
        raise Exception(f"Error from mcp_server.py: {stderr_output}")
    raise Exception("No valid JSON-RPC response received from mcp_server.py")

def main():
    templates = get_available_templates()
    if not templates:
        print("No templates found in scanner/templates directory.")
        return

    # Hiển thị danh sách template
    print("Available templates:")
    for i, template in enumerate(templates, 1):
        print(f"{i}. {template}")

    # Nhập URL mục tiêu và template
    target_url = input("Enter target URL (e.g., http://testphp.vulnweb.com/): ").strip()
    try:
        template_choice = int(input("Choose template number: "))
        if template_choice < 1 or template_choice > len(templates):
            raise ValueError("Invalid template number")
    except ValueError as e:
        print(f"Error: {e}")
        return

    template_path = templates[template_choice - 1]

    # Gửi yêu cầu quét theo chuẩn JSON-RPC
    request = {
        "jsonrpc": "2.0",
        "method": "call_tool",
        "params": {
            "tool_name": "nuclei_scan",
            "args": {
                "urls": [target_url],
                "template_paths": [template_path]
            }
        },
        "id": 1
    }

    try:
        result = call_mcp_server(request)
        if result:
            print("Scan completed. Found vulnerabilities.")
            print("Check logs/results.log for details.")
        else:
            print("No vulnerabilities found.")
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        # Đảm bảo tiến trình mcp_server.py được dừng
        process = subprocess.Popen(
            ["python", "mcp_server.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        process.terminate()

if __name__ == "__main__":
    main()