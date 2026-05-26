from typing import TypedDict, List, Optional, Literal

class Task(TypedDict):
    task_id: str
    tool: str
    args: str
    purpose: str
    status: Literal["pending", "running", "completed", "failed"]

class Finding(TypedDict):
    host: str
    port: Optional[int]
    service: Optional[str]
    title: str
    severity: Literal["critical","high","medium","low","info"]
    description: str
    evidence: str
    remediation: str

class AgentState(TypedDict):
    target: str
    scan_type: str
    plan: List[Task]
    findings: List[Finding]
    phase: str
    error: Optional[str]
    final_report: Optional[str]