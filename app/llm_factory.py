"""
Specter-OS — LLM Provider Factory
Dynamically provisions the requested Language Model backend (Ollama, Gemini, OpenRouter)
based on environment configuration, eliminating direct coupling to a single provider.
"""

from langchain_core.language_models.chat_models import BaseChatModel
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("llm_factory")

def get_llm(temperature: float = 0.0, format_type: str = None) -> BaseChatModel:
    """
    Returns a configured LangChain ChatModel instance based on `LLM_PROVIDER`.
    
    Args:
        temperature: Sampling temperature (0.0 for deterministic RED TEAM logic)
        format_type: Set to 'json' to force structured JSON output (if supported)
        
    Returns:
        BaseChatModel
    """
    provider = settings.llm_provider.lower().strip()
    model_name = settings.specter_llm_model
    
    if provider == "ollama":
        from langchain_community.chat_models import ChatOllama
        
        logger.debug(f"[LLM Factory] Provisioning Local Ollama: {model_name} @ {settings.ollama_base_url}")
        
        kwargs = {
            "model": model_name,
            "base_url": settings.ollama_base_url,
            "temperature": temperature,
        }
        
        if format_type == "json":
            kwargs["format"] = "json"
            
        return ChatOllama(**kwargs)

    elif provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        
        logger.debug(f"[LLM Factory] Provisioning Google Gemini: {model_name}")
        if not settings.gemini_api_key:
            logger.warning("GEMINI_API_KEY is missing! Initializing Gemini anyway but it will fail on invocation.")

        return ChatGoogleGenerativeAI(
            model=model_name,
            temperature=temperature,
            google_api_key=settings.gemini_api_key
        )
        
    else:
        logger.error(f"[LLM Factory] Unknown configured LLM_PROVIDER '{provider}'. Defaulting to Local Ollama.")
        from langchain_community.chat_models import ChatOllama
        return ChatOllama(model="llama3.1", base_url=settings.ollama_base_url, temperature=temperature)
