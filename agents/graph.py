from langgraph.graph import StateGraph, END
from agents.state import AgentState
from agents.planner import planner_node
from agents.analyst import analyst_node
from agents.writer import writer_node
from agents.educational_attack_simulator import EducationalAttackSimulator

async def attack_simulator_node(state: AgentState) -> AgentState:
    sim = EducationalAttackSimulator()
    demos = sim.run_all_demos()
    report = EducationalAttackSimulator.build_attack_summary_email(demos)
    state["final_report"] = report
    state["phase"] = "finished"
    return state

async def entry_router(state: AgentState) -> str:
    if state["scan_type"] == "ai_demo":
        return "attack_simulator"
    return "planner"

async def route_after_plan(state: AgentState) -> str:
    return "analyst"

async def route_after_analyst(state: AgentState) -> str:
    if state["phase"] == "reporting":
        return "writer"
    else:
        return "analyst"

def create_app():
    workflow = StateGraph(AgentState)
    workflow.add_node("planner", planner_node)
    workflow.add_node("analyst", analyst_node)
    workflow.add_node("writer", writer_node)
    workflow.add_node("attack_simulator", attack_simulator_node)

    workflow.set_conditional_entry_point(
        entry_router,
        {
            "planner": "planner",
            "attack_simulator": "attack_simulator"
        }
    )
    workflow.add_conditional_edges("planner", route_after_plan, {"analyst": "analyst"})
    workflow.add_conditional_edges("analyst", route_after_analyst, {
        "analyst": "analyst",
        "writer": "writer"
    })
    workflow.add_edge("writer", END)
    workflow.add_edge("attack_simulator", END)

    return workflow.compile()