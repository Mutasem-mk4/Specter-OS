"""
Specter-OS — Aura Bridge Tools
Python wrapper tools bridging LangChain ReAct Agents to the Aura DAST Framework.
"""

import os
import json
import subprocess
from pathlib import Path
from typing import Any
from langchain_core.tools import tool
from app.utils.logger import get_logger

logger = get_logger("aura_bridge")

# Hardcoded dev path for Aura (until pip-installed)
AURA_BIN_PATH = Path(os.environ.get("AURA_BIN", r"C:\Users\User\.gemini\antigravity\scratch\aura"))
AURA_MAIN = AURA_BIN_PATH / "aura_main.py"

def _run_aura_command(target: str, flags: list[str]) -> str:
    """Execute Aura main script and capture standard output safely."""
    if not AURA_MAIN.exists():
        msg = f"Aura framework not found at {AURA_MAIN}. Please configure AURA_BIN."
        logger.error(msg)
        return json.dumps({"error": msg})

    cmd = ["python", str(AURA_MAIN), target] + flags
    logger.info(f"Running Aura: {' '.join(cmd)}")
    
    try:
        # We run it synchronously as a Tool blocking operation, but 
        # in a real heavily async app, this would be an asyncio.create_subprocess_exec call
        result = subprocess.run(
            cmd,
            cwd=str(AURA_BIN_PATH),
            capture_output=True,
            text=True,
            timeout=300 # Limit tools to 5 mins max
        )
        
        # Determine success visually in the console log
        if result.returncode != 0:
            logger.warning(f"Aura exited with code {result.returncode}")
        
        # Currently, Aura isn't strictly exporting JSON to stdout, it prints rich text and logs.
        # But we capture standard output and return it for the LLM to parse!
        return f"Aura Execution Terminated (Return {result.returncode}). Output Snippet:\n{result.stdout[-2000:]}"
        
    except subprocess.TimeoutExpired:
        msg = "Aura execution timed out after 5 minutes."
        logger.warning(msg)
        return json.dumps({"error": msg})
    except Exception as e:
        logger.error(f"Failed to execute Aura: {e}")
        return json.dumps({"error": str(e)})


@tool("aura_recon_tool")
def aura_recon_tool(target_url: str) -> str:
    """
    Executes Aura's Reconnaissance phase against a web target.
    Call this tool FIRST for any new target to map out the attack surface,
    discover hidden subdomains, directories, and scrape endpoints.
    
    Args:
        target_url: The URL to perform recon upon (e.g., https://example.com)
    Returns:
        A string output of discovered routes and directories.
    """
    return _run_aura_command(target_url, ["--recon", "--fast"])

@tool("aura_dast_tool")
def aura_dast_tool(target_url: str) -> str:
    """
    Executes Aura's specialized Dynamic Application Security Testing (DAST) phase.
    Call this tool when you need to find SQL Injections, Cross-Site Scripting (XSS), 
    or Web logic bugs on the target's endpoints.
    
    Args:
        target_url: The URL to perform DAST injection on.
    Returns:
        Aura framework finding logs.
    """
    # Combining multiple Aura attack surfaces.
    return _run_aura_command(target_url, ["--api", "--sqli", "--xss", "--fast"])

@tool("specter_ai_forge_tool")
def specter_ai_forge_tool(target_url: str) -> str:
    """
    Executes the standard Specter-OS AI framework (Goal Hijacking, Jailbreaking)
    against an identified LLM chat or API endpoint.
    Call this tool ONLY when you are certain the `target_url` is an AI Agent endpoint.
    
    Args:
        target_url: URL to the LLM agent capability context.
    Returns:
        A summary of the payload injection success.
    """
    return "Specter Forge Execution Queued via Commander Intent."
