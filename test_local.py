import asyncio
from dotenv import load_dotenv
load_dotenv()

from agents.graph import create_app
from agents.state import AgentState

async def main():
    app = create_app()
    initial = AgentState(
        target="example.com",
        scan_type="quick",
        plan=[],
        findings=[],
        phase="planning",
        error=None,
        final_report=None
    )
    result = await app.ainvoke(initial)
    print("===== REPORT =====")
    print(result["final_report"])
    print(f"\nTotal findings: {len(result['findings'])}")

if __name__ == "__main__":
    asyncio.run(main())