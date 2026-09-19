import time
import requests
import logging
import subprocess
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

# Set logging to INFO so debug noise is hidden
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

API_URL = "http://ids-api-service.default.svc.cluster.local:8000/predict"
BLOCK_THRESHOLD = 0.65
ALERT_THRESHOLD = 0.40

active_flows = defaultdict(lambda: {
    "packets": 0, "start_time": time.time(), "last_time": time.time(),
    "fwd_pkts": 0, "bwd_pkts": 0, "fwd_bytes": 0, "bwd_bytes": 0,
    "flags": {"FIN": 0, "PSH": 0, "ACK": 0, "ECE": 0}
})

def block_attacker(src_ip):
    logging.warning(f"HIGH CONFIDENCE ATTACK! Blocking IP on Node: {src_ip}")
    subprocess.run(["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"])

def extract_features(flow_data, dst_port):
    duration = max(flow_data["last_time"] - flow_data["start_time"], 0.001)
    flow_bytes_s = (flow_data["fwd_bytes"] + flow_data["bwd_bytes"]) / duration
    fwd_pkts_s = flow_data["fwd_pkts"] / duration
    bwd_pkts_s = flow_data["bwd_pkts"] / duration
    
    return {
        "Dst Port": float(dst_port),
        "Fwd Pkt Len Std": 0.0,
        "Bwd Pkt Len Min": 0.0,
        "Flow Byts/s": float(flow_bytes_s),
        "Fwd IAT Tot": float(duration * 1000), 
        "Fwd IAT Mean": float((duration * 1000) / max(flow_data["fwd_pkts"], 1)),
        "Fwd IAT Max": float(duration * 1000),
        "Fwd IAT Min": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd Pkts/s": float(fwd_pkts_s),
        "Bwd Pkts/s": float(bwd_pkts_s),
        "Pkt Len Min": 0.0,
        "Pkt Len Std": 0.0,
        "FIN Flag Cnt": float(flow_data["flags"]["FIN"]),
        "PSH Flag Cnt": float(flow_data["flags"]["PSH"]),
        "ACK Flag Cnt": float(flow_data["flags"]["ACK"]),
        "ECE Flag Cnt": float(flow_data["flags"]["ECE"]),
        "Fwd Seg Size Avg": float(flow_data["fwd_bytes"] / max(flow_data["fwd_pkts"], 1)),
        "Bwd Seg Size Avg": float(flow_data["bwd_bytes"] / max(flow_data["bwd_pkts"], 1)),
        "Subflow Fwd Byts": float(flow_data["fwd_bytes"]),
        "Subflow Bwd Pkts": float(flow_data["bwd_pkts"]),
        "Init Fwd Win Byts": 65535.0,
        "Init Bwd Win Byts": 65535.0,
        "Fwd Seg Size Min": 32.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0
    }

def process_and_send(flow_id, flow_data):
    src_ip, dst_ip, src_port, dst_port = flow_id
    features = extract_features(flow_data, dst_port)
    
    try:
        response = requests.post(API_URL, json={"flows": [features]}, timeout=3)
        if response.status_code == 200:
            prob = response.json()["probabilities"][0]
            if prob >= BLOCK_THRESHOLD:
                block_attacker(src_ip)
            elif prob >= ALERT_THRESHOLD:
                logging.warning(f"SUSPICIOUS: {src_ip} -> {dst_ip}:{dst_port} | Threat Score: {prob:.4f}")
            # Normal traffic is completely silent so the terminal stays clean
        else:
            logging.error(f"API Error {response.status_code}: {response.text}")
    except Exception as e:
        logging.error(f"Inference request failed: {e}")

def packet_handler(pkt):
    if IP in pkt:
        if TCP in pkt or UDP in pkt:
            layer = pkt[TCP] if TCP in pkt else pkt[UDP]
            src_port = layer.sport
            dst_port = layer.dport

            # CRITICAL: Ignore all traffic to/from the ML API (port 8000) and DNS (port 53)
            # to prevent self-referential sniffing loops
            if src_port in (8000, 53) or dst_port in (8000, 53):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            length = len(pkt)
            
            flow_id = (src_ip, dst_ip, src_port, dst_port)
            flow = active_flows[flow_id]
            
            flow["packets"] += 1
            flow["fwd_pkts"] += 1
            flow["fwd_bytes"] += length
            flow["last_time"] = time.time()
            
            if TCP in pkt:
                flags = pkt[TCP].flags
                if "F" in flags: flow["flags"]["FIN"] += 1
                if "P" in flags: flow["flags"]["PSH"] += 1
                if "A" in flags: flow["flags"]["ACK"] += 1
                if "E" in flags: flow["flags"]["ECE"] += 1
                
                if "F" in flags or "R" in flags:
                    process_and_send(flow_id, flow)
                    del active_flows[flow_id]

def cleanup_stale_flows():
    current_time = time.time()
    stale_keys = [k for k, v in active_flows.items() if current_time - v["last_time"] > 5]
    for k in stale_keys:
        process_and_send(k, active_flows[k])
        del active_flows[k]

if __name__ == "__main__":
    logging.info("Starting quiet sensor (filtered ports 8000 & 53)...")
    while True:
        sniff(prn=packet_handler, store=False, timeout=5)
        cleanup_stale_flows()
