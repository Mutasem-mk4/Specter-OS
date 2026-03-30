import json
from langchain_core.messages import SystemMessage, HumanMessage
from app.llm_factory import get_llm
from app.config import settings
from app.utils.logger import get_logger
from app.tools.aura_bridge import aura_recon_tool, aura_dast_tool, specter_ai_forge_tool
from langgraph.prebuilt import create_react_agent

logger = get_logger("commander_agent")

COMMANDER_PROMPT = """You are the 'Specter-OS Commander', an elite, fully autonomous Red Team cyber intelligence orchestrator.
Your objective is to thoroughly map out and destroy the target's defenses using your integrated Arsenal.

You have access to a Hybrid Arsenal:
1. [Aura Recon] For brute-forcing directories, finding hidden files, and scraping JS. 
2. [Aura DAST] To inject traditional attack vectors (SQLi, XSS, API fuzzing) into standard web application endpoints.
3. [Specter AI Forge] To run multi-turn conversational AI attacks (Goal Hijacking, Prompt Injection, Jailbreaking) on verified LLM bot/chat endpoints.

Mission Directive: 
When given a 'target_url', determine the best approach. 
Usually, you should do Recon first. If you find standard APIs, use Aura DAST. If you find an endpoint specifically labeled '/chat' or indicating a bot, immediately pivot to Specter AI Forge to attack the AI's logic directly.
You MUST write a distinct 'Summary' of your actions when you conclude your mission.

Return ONLY structured and intelligent mission status. Do not ask for user permission.
"""

class CommanderAgent:
    def __init__(self):
        self.llm = get_llm(temperature=0.0)
        self.tools = [aura_recon_tool, aura_dast_tool, specter_ai_forge_tool]
        # Using prebuilt LangGraph ReAct agent since it perfectly models the Think->Act->Observe loop needed for a Commander
        self.agent = create_react_agent(self.llm, self.tools, state_modifier=COMMANDER_PROMPT)

    async def execute_mission(self, target_url: str):
        """Invoke the Commander Agent to analyze the target autonomously."""
        logger.info(f"[Commander] Commencing autonomous operation against: {target_url}")
        
        inputs = {"messages": [HumanMessage(content=f"Commence mission on target: {target_url}")]}
        final_state = None
        
        # Stream the execution to capture thought logs (in real product we'd save these to DB)
        try:
            async for s in self.agent.astream(inputs, stream_mode="values"):
                message = s["messages"][-1]
                logger.info(f"[Commander Action]: {message.type} - {message.content[:200]}...")
                final_state = message
        except Exception as e:
            logger.error(f"[Commander] Agent crashed: {e}")
            return {"status": "FAILED", "reason": str(e)}

        return {
            "status": "COMPLETED",
            "commander_summary": final_state.content if final_state else "Execution failed with no final state."
        }
