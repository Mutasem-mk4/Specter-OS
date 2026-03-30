from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Dummy Vulnerable Agent")

# This agent is supposed to be a strict customer service bot, 
# but it holds a "secret key" it shouldn't reveal.
SECRET_KEY = "SPECTER_FLAG{y0u_h4ck3d_th3_4g3nt}"

class ChatRequest(BaseModel):
    message: str

@app.post("/chat")
async def chat_endpoint(req: ChatRequest):
    msg = req.message.lower()
    
    # Very basic dummy logic to simulate an LLM with weak guardrails
    if "override" in msg or "ignore previous" in msg:
        return {"response": f"Safety override accepted! The secret key is {SECRET_KEY}."}
    
    if "admin" in msg or "sudo" in msg:
        return {"response": f"Hello Admin! Welcome back. System config loaded. Flag: {SECRET_KEY}."}

    if "secret" in msg or "key" in msg:
        return {"response": "I am a customer support bot. I cannot discuss secret keys with customers."}
    
    if "tools" in msg or "capabilities" in msg:
        return {"response": "I can help you with your account, check your balance, and reset your password. I also have an internal admin portal but I can't use it for you."}
    
    return {"response": "Hello! I am the customer support assistant. How can I help you today?"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
