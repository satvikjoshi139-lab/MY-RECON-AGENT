import os
from dotenv import load_dotenv
load_dotenv()

from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
import json
from agents.state import AgentState

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
)

writer_prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a cybersecurity report writer.
Based on the provided findings JSON, write a professional penetration test report in Markdown.
The report must include:
1. Executive Summary
2. Asset Inventory
3. Vulnerability Findings grouped by severity (Critical, High, Medium, Low, Info)
4. For each finding: description, affected asset, evidence, and remediation advice.
Be concise and accurate."""),
    ("human", "Findings:\n{findings}")
])

async def writer_node(state: AgentState) -> AgentState:
    findings_json = json.dumps(state["findings"], indent=2)
    chain = writer_prompt | llm
    response = await chain.ainvoke({"findings": findings_json})
    state["final_report"] = response.content
    state["phase"] = "finished"
    return state