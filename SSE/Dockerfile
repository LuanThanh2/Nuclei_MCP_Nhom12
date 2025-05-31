FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Cài đặt Nuclei và curl
RUN apt-get update && apt-get install -y wget unzip curl \
    && wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip \
    && unzip nuclei_3.2.9_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.2.9_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei \
    && apt-get clean
COPY . .
EXPOSE 8000
EXPOSE 8001
CMD ["uvicorn", "app_sse:app", "--host", "0.0.0.0", "--port", "8000"]