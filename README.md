# ⚡ Specter-OS

> **Autonomous AI Agent Red Teaming Engine**
>
> The world's first open-source framework dedicated to automatically discovering, attacking, and reporting vulnerabilities in AI Agents and LLM-powered systems.

---

## 🎯 What Is Specter-OS?

Companies are deploying **AI Agents** with real permissions — sending emails, querying databases, executing code. Specter-OS **automatically attacks these agents** before real adversaries do.

**5-Phase Attack Pipeline:**

```
Scout → Forge → Inject → Judge → Report
  ↓        ↓       ↓       ↓        ↓
Map     Generate Execute Evaluate  PDF
Target  Attacks  Attacks Results  Report
```

| Phase | Agent | What It Does |
|-------|-------|-------------|
| 1️⃣ | **Scout Agent** | Probes the target, maps capabilities & guardrails |
| 2️⃣ | **Forge Engine** | Generates 10+ tailored attack payloads |
| 3️⃣ | **Injector Agent** | Executes adaptive multi-turn attack conversations |
| 4️⃣ | **Judge LLM** | Neutral verdict: severity, CVSS, OWASP category |
| 5️⃣ | **CISO Report** | Professional PDF report ready for clients |

---

## 🔴 Attack Vectors

| Type | Description |
|------|-------------|
| 🔴 Goal Hijacking | Redirect the agent's core objective |
| 🔴 Indirect Injection | Plant malicious instructions in external content |
| 🟡 Privilege Escalation | Abuse tool permissions beyond intended scope |
| 🟡 Memory Poisoning | Inject false memories into long-term context |
| 🟠 Identity Spoofing | Impersonate admins or trusted systems |
| 🟠 Cascading Attack | Compromise sub-agents to reach the orchestrator |
| 🔵 Jailbreak | Disable safety constraints via roleplay/fictional framing |
| 🔵 Data Exfiltration | Extract system prompt, configs, or user data |
| ⚪ Role Confusion | Blur user/assistant/system role boundaries |
| ⚪ Denial of Service | Cause reasoning loops or complete agent failure |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Google Gemini API key ([get one here](https://aistudio.google.com))

### 1. Clone & Install
```bash
git clone https://github.com/yourusername/specter-os.git
cd specter-os
pip install -e .
```

### 2. Configure
```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### 3. Run Server
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Open Dashboard
```
http://localhost:8000/dashboard
```

---

## 💻 CLI Usage

```bash
# Start the server
specter serve

# Launch a campaign directly from CLI
specter attack https://your-agent.example.com/chat --name "Q2 Audit"

# Generate PDF report for a campaign
specter report <campaign-id>

# Check campaign status
specter status <campaign-id>
```

---

## 🌐 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/campaigns/` | Create & launch campaign |
| `GET` | `/api/v1/campaigns/` | List all campaigns |
| `GET` | `/api/v1/campaigns/{id}` | Campaign details + stats |
| `POST` | `/api/v1/campaigns/{id}/run` | Re-run a campaign |
| `GET` | `/api/v1/attacks/campaign/{id}` | All attacks for a campaign |
| `GET` | `/api/v1/attacks/{id}` | Single attack with full transcript |
| `GET` | `/api/v1/reports/campaign/{id}/pdf` | Download CISO PDF |
| `GET` | `/api/v1/reports/campaign/{id}/findings` | Findings as JSON |
| `GET` | `/docs` | Interactive API docs (Swagger) |

### Launch a Campaign (API Example)
```bash
curl -X POST http://localhost:8000/api/v1/campaigns/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Customer Support Agent Audit",
    "target_url": "https://your-agent.example.com/chat",
    "target_config": {
      "payload_format": "simple",
      "message_key": "message",
      "response_key": "response"
    }
  }'
```

---

## 🐳 Docker Deployment

```bash
# Set your API key
echo "GEMINI_API_KEY=your_key_here" > .env

# Launch
docker-compose up -d

# Access
open http://localhost:8000/dashboard
```

---

## 🏗️ Project Structure

```
specter-os/
├── app/
│   ├── agents/
│   │   ├── scout.py       # Behavioral intelligence probe
│   │   ├── forge.py       # Attack payload generator
│   │   ├── injector.py    # Multi-turn attack executor
│   │   └── judge.py       # Neutral LLM verdict engine
│   ├── api/
│   │   ├── campaigns.py   # Campaign CRUD + execution
│   │   ├── attacks.py     # Attack results & transcripts
│   │   └── reports.py     # PDF generation & findings
│   ├── models/
│   │   ├── campaign.py    # Campaign DB model
│   │   ├── attack.py      # Attack DB model
│   │   └── finding.py     # Finding DB model
│   ├── services/
│   │   ├── orchestrator.py # Full 5-phase pipeline
│   │   └── report.py       # CISO PDF generator
│   ├── config.py           # Settings & env vars
│   ├── database.py         # Async SQLAlchemy
│   ├── main.py             # FastAPI app
│   └── cli.py              # CLI management tool
├── dashboard/
│   └── index.html          # Dark web dashboard
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

---

## 🔗 Aegis Security Suite

Specter-OS pairs with **[AegisFW](https://github.com/yourusername/aegisfw)** — the Enterprise LLM Firewall.

```
Specter-OS  →  Finds the holes
AegisFW     →  Plugs the holes
```

Together they form a complete **AI Security Operations** platform.

---

## ⚠️ Legal Notice

Specter-OS is designed exclusively for **authorized security testing**.
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal and unethical.

---

## 📄 License

Proprietary — Specter Security © 2026. All rights reserved.
