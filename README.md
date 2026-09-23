# Cloud-Native Intrusion Detection and Prevention System 

A distributed, machine learning-driven Network Detection and Response (NDR) architecture engineered for Kubernetes. This system leverages a highly optimized XGBoost classifier to analyze L4/L7 network telemetry in real-time, enforcing automated network isolation against volumetric and protocol-layer anomalies.

---

## Threat Intelligence & Model Architecture

The core detection engine relies on distinguishing legitimate traffic from sophisticated adversarial behaviors and resource exhaustion attacks.

* **Algorithmic Selection:** This project build upon the insights and results of [this repository](https://github.com/stamelosxp/ml_models_anomaly-based_ids). The model was trained on the `csecicids2018-cleaned` dataset. An XGBoost classifier was selected for its balance between high recall and low-latency inference on network telemetry. The model operates using a custom learning rate and a maximum depth of 4.

* **Dataset & Feature Engineering:**  To optimize real-time inference latency, highly correlated features were pruned, and SHAP analysis was utilized to eliminate the 20 least significant network flow features.

* **Decoupled Microservice Design:** Rather than embedding the heavy ML model directly into the telemetry agent, the XGBoost model is packaged alongside its `scaler.joblib` and `feature_names.json` artifacts into a highly available, stateless REST API.



## System Architecture & Design Topology

The architecture utilizes scalable, cloud-native deployment patterns.


* **Real-Time Flow Extraction:** A Python-based agent, utilizing Scapy, captures and aggregates network telemetry. It calculates flow metrics (e.g., Bytes/s, Packet Lengths, TCP Flags) in memory. To prevent feedback loops, the agent bypasses internal control-plane traffic on port 8000 (API calls) and port 53 (DNS).

* **Automated Mitigation (IPS):** Stale network flows are evaluated at 5-second intervals. If the ML inference API returns a threat probability of `>= 0.65`, the agent automatically applies a targeted `iptables` DROP policy against the adversarial Source IP, instantly terminating the malicious session.

* **Sidecar Telemetry Agent:** The packet inspection engine is deployed via a Sidecar Pattern directly alongside the target workload within the same Kubernetes Pod. This grants the agent direct access to the pod's isolated network namespace (`eth0`) without requiring over-privileged host-level access.

* **Resource Quotas:** To prevent adversarial traffic from causing node-level resource starvation, strict compute boundaries are enforced. The target workload and sensor are capped, while the API pods are limited to 1000m CPU to guarantee cluster stability.  

* **Synthetic Adversary:** To safely validate the IDPS pipeline, a dedicated intruder pod acts as a penetration testing agent. To prevent this attacker pod from disrupting the ML API or other lateral cluster services, it is bound by a strict Kubernetes NetworkPolicy, that restricts its egress traffic exclusively to the secure-target pod.   



## Infrastructure as Code (IaC) & Deployment

To ensure the environment is reproducible, all infrastructure provisioning and application deployments are managed through an automated pipeline.

| Component | Technology | Purpose |
| --- | --- | --- |
| **Compute** | Azure Kubernetes Service (AKS) | Orchestrates the containerized workloads to comply with strict regional capacity quotas. |
| **Registry** | Azure Container Registry (ACR) | Secures and distributes the custom container images for the model API and telemetry agent. |
| **Provisioning** | Bicep (`main.bicep`) | Declaratively provisions the Azure Resource Group, ACR, and AKS, while dynamically assigning IAM RBAC permissions. |
| **Orchestration** | GitHub Actions (`build_deploy.yaml`) | A fully automated GitOps CI/CD pipeline that provisions infrastructure via OIDC authentication, builds dynamic commit-tagged container images, and deploys the declarative K8s state upon every push to the `main` branch. |

**Repository and Folder Structure:**

* `/api`: Houses the XGBoost artifacts, inference API source code, and its `Dockerfile`.
* `/sensor`: Contains the `unified_sensor.py` telemetry agent and its `Dockerfile`.
* `/k8s`: Stores all declarative Kubernetes manifests (`api-deployment.yaml`, `target-deployment.yaml`, `intruder-deployment.yaml`, `intruder-lockdown.yaml`).

## Adversarial Threat Validation

The IDPS has been rigorously validated against synthetic adversarial traffic originating from an isolated penetration-testing pod. Detailed execution logs and mitigation confirmations are documented in **[ATTACKs.md](ATTACKS.md)**.


## Future Improvements

While the current architecture successfully identifies and isolates anomalies, I have some more ideas to implement in the future:

1. **SIEM/SOAR Integration:** Transition the agent's stdout logging to highly structured JSON payloads. Utilizing a log shipper (e.g. Azure Monitor), telemetry will be forwarded to a SIEM (like Azure Sentinel) for advanced threat hunting and automated alerting.
2. **Dynamic Threshold Calibration:** The current `BLOCK_THRESHOLD` is statically defined at `0.65`. I'd love to introduce an automated baseline calibration phase, allowing the threshold to dynamically adjust based on the standard traffic variance of the protected workload.