# 🤖 Multi-Agent Cyber Recon Scanner

A **free, serverless-ready, multi-agent cybersecurity reconnaissance system** that automatically plans, performs, and reports on security reconnaissance tasks. Built with **LangChain**, **LangGraph**, **Groq**, and **Vercel**.

> 🚀 Deploy with one command using only free services
> 💸 Powered by Groq Free Tier + Vercel Hobby
> 🔴🟡🟢 Live risk badge instantly highlights target exposure level

---

# 🧠 How It Works

Three intelligent agents collaborate under a LangGraph supervisor:

| Agent               | Role                                                                                                                                      |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Recon Planner**   | Breaks the target into structured reconnaissance tasks like subdomain enumeration, port scanning, HTTP probing, and vulnerability checks  |
| **Surface Analyst** | Executes each task safely using lightweight, serverless-friendly tooling such as `crt.sh`, socket connections, and `aiohttp`              |
| **Report Writer**   | Converts raw findings into a professional Markdown penetration testing report with asset inventory, risk analysis, and remediation advice |

The platform also includes an **AI Security Demo** that safely simulates **6 real-world AI agent attack patterns** including prompt injection and tool hijacking.

---

# ✨ Features

* 🔍 **Reconnaissance**

  * Subdomain enumeration
  * DNS lookups
  * Open port detection
  * HTTP header analysis
  * Missing security header detection
  * Exposed `.git` directory checks

* 📋 **Professional Markdown Reports**

  * Executive summary
  * Asset inventory
  * Severity-grouped findings
  * Remediation recommendations

* 🟢🟡🔴 **Live Risk Indicator**

  * **Red** → High risk
  * **Yellow** → Medium risk
  * **Green** → Low risk

* 🤖 **AI Security Demo**

  * 6 simulated AI-agent attacks
  * CAPEC benchmark mapping
  * Fully educational and safe

* ⚡ **Web Dashboard**

  * Add multiple targets
  * Launch scans simultaneously
  * View reports instantly

* 💸 **Completely Free**

  * Uses Groq free tier
  * Deploys on Vercel Hobby
  * No paid APIs required

* 🛡️ **Serverless Friendly**

  * No heavy binaries
  * No Docker required
  * Optimized for Vercel Functions

---

# 🏗️ Architecture

```text
                    ┌────────────────────┐
                    │     Web UI         │
                    │   (Next.js App)    │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ LangGraph Supervisor│
                    └─────────┬──────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│ Recon Planner  │  │ Surface Analyst│  │ Report Writer  │
└────────────────┘  └────────────────┘  └────────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
 Recon Tasks         Safe Recon Tools         Markdown Report
```

---

# 📁 Folder Structure

```bash
multi-agent-cyber-recon/
│
├── app/                        # Next.js frontend + API routes
│   ├── api/
│   │   ├── scan/
│   │   └── report/
│   ├── dashboard/
│   └── page.tsx
│
├── agents/                     # LangGraph agents
│   ├── recon_planner.py
│   ├── surface_analyst.py
│   ├── report_writer.py
│   └── supervisor.py
│
├── tools/                      # Lightweight recon utilities
│   ├── crtsh.py
│   ├── dns_lookup.py
│   ├── port_scan.py
│   ├── http_probe.py
│   └── security_headers.py
│
├── demos/                      # AI security simulations
│   ├── prompt_injection.py
│   ├── tool_hijacking.py
│   └── capec_mapping.py
│
├── reports/                    # Generated markdown reports
│
├── public/
│
├── styles/
│
├── requirements.txt
├── package.json
├── vercel.json
├── README.md
└── .env.example
```

---

# ⚙️ Tech Stack

| Layer        | Technology             |
| ------------ | ---------------------- |
| Frontend     | Next.js + Tailwind CSS |
| Backend      | Python + FastAPI       |
| AI Framework | LangChain + LangGraph  |
| LLM Provider | Groq                   |
| Deployment   | Vercel                 |
| Networking   | aiohttp + socket       |
| Reporting    | Markdown               |

---

# 🚀 Quick Start

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/multi-agent-cyber-recon.git

cd multi-agent-cyber-recon
```

---

## 2️⃣ Install Dependencies

### Python

```bash
pip install -r requirements.txt
```

### Node.js

```bash
npm install
```

---

## 3️⃣ Configure Environment Variables

Create a `.env.local` file:

```env
GROQ_API_KEY=your_groq_api_key
```

---

## 4️⃣ Run Locally

```bash
npm run dev
```

Frontend:

```text
http://localhost:3000
```

---

# ☁️ Deploy to Vercel

## One-Click Deploy

```bash
vercel
```

Or import the repository directly into Vercel.

---

# 🔒 Security Philosophy

This project is designed for:

* Defensive security research
* Educational demonstrations
* Authorized reconnaissance only

It intentionally avoids:

* Exploitation
* Malware functionality
* Destructive scanning
* Heavy offensive tooling

---

# 🤖 AI Security Demo

The built-in AI Security Demo simulates:

| Attack Type       | Description                      |
| ----------------- | -------------------------------- |
| Prompt Injection  | Malicious instruction override   |
| Tool Hijacking    | Manipulating agent tool calls    |
| Data Exfiltration | Unauthorized information leakage |
| Context Poisoning | Corrupting memory/context        |
| Jailbreaking      | Circumventing safeguards         |
| Recursive Abuse   | Infinite agent loop attacks      |

Each scenario includes:

* CAPEC mapping
* Risk explanation
* Mitigation guidance
* Safe simulated output

---

# 📋 Example Report Output

```markdown
# Executive Summary

Target: example.com
Risk Level: 🔴 High

## Findings

- Missing Content-Security-Policy header
- Exposed Git repository detected
- Port 8080 publicly accessible

## Recommendations

- Disable public Git access
- Add security headers
- Restrict unnecessary services
```

---

# 🛠️ Future Improvements

* ASN intelligence
* WHOIS enrichment
* CVE correlation
* Screenshot capture
* Historical scan comparison
* Slack/Discord alerts
* Multi-tenant dashboards

---

# 📜 License

MIT License

---

# ⚠️ Disclaimer

This tool is intended **only for authorized security testing and educational purposes**.

Users are responsible for complying with all applicable laws and regulations. Unauthorized scanning or testing of systems without permission is prohibited.

---

# ❤️ Acknowledgements

Built with:

* LangChain
* LangGraph
* Groq
* Vercel
* Next.js
* FastAPI

---

# 🌟 Support

If you found this project useful:

* ⭐ Star the repository
* 🍴 Fork the project
* 🛡️ Contribute improvements
* 🐛 Submit issues and ideas
