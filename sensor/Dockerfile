FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sensor

# Scapy for native Python packet sniffing
RUN pip install --no-cache-dir scapy requests

COPY unified_sensor.py .

CMD ["python", "unified_sensor.py"]