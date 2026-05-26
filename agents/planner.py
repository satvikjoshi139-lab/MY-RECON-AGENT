import os
from dotenv import load_dotenv
load_dotenv()

from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
import json, uuid
from agents.state import AgentState, Task

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    model_kwargs={"response_format": {"type": "json_object"}}
)

planner_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a security reconnaissance planner.
Given a target and scan type, produce a JSON object exactly in the following format:
{{
  "tasks": [
    {{"tool": "subdomain_enum", "args": "example.com", "purpose": "..."}},
    {{"tool": "dns_resolve", "args": "example.com", "purpose": "..."}},
    ...
  ]
}}

Available tools:
- subdomain_enum (args: domain) : finds subdomains
- dns_resolve (args: hostname) : resolves to IPs
- port_scan (args: ip) : checks common ports
- http_probe (args: url) : probes HTTP/HTTPS service
- vuln_scan (args: url) : runs light vulnerability checks

Create a logical, ordered plan. Start with passive discovery (subdomain_enum), then DNS, then ports, then HTTP probes, and finally vuln scans on live HTTP services."""),
    ("human", "Target: {target}, Scan type: {scan_type}")
])

async def planner_node(state: AgentState) -> AgentState:
    chain = planner_prompt | llm
    response = await chain.ainvoke({"target": state["target"], "scan_type": state["scan_type"]})
    try:
        plan_data = json.loads(response.content)
        tasks = plan_data.get("tasks", [])
    except Exception:
        tasks = []

    state["plan"] = [
        Task(
            task_id=str(uuid.uuid4())[:8],
            tool=t["tool"],
            args=t["args"],
            purpose=t["purpose"],
            status="pending"
        ) for t in tasks
    ]
    state["phase"] = "analysis"
    return state