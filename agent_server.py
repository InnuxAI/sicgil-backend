from agno.agent import Agent
from agno.models.google import Gemini
from agno.os import AgentOS
from agno.tools.mcp import MCPTools
from agno.session import SessionSummaryManager
from agno.db.mongo import MongoDb
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from backend.database.mongodb import mongodb, MongoDB
from backend.auth.middleware import auth_middleware
from backend.auth.service import auth_service
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from datetime import datetime
from uuid import uuid4
from typing import Dict, Any, Optional
import os

load_dotenv(".env")

# Initialize Agno MongoDB for session storage
agno_db = MongoDb(
    db_url=os.getenv("MONGODB_URL", "mongodb://localhost:27017"),
    db_name=os.getenv("MONGODB_DB_NAME", "agentdb"),
    session_collection="agent_sessions",  # Collection name for agent sessions
    memory_collection="agent_memory",
    metrics_collection="agent_metrics"
)

# Configure session summary manager with custom prompt for short titles
session_summary_manager = SessionSummaryManager(
    model=Gemini(id="gemini-2.0-flash-exp"),  # Use faster model for summaries
    session_summary_prompt="Create a very short 3-5 word title that captures the essence of this conversation. Be concise and descriptive.",
)

# MCP Tools
code_mcp = MCPTools(
    transport="streamable-http", 
    url=os.getenv("MCP_CODE_SERVER_URL", "http://localhost:8000/mcp"), 
    timeout_seconds=int(os.getenv("MCP_TIMEOUT_SECONDS", "60"))
)
excel_mcp = MCPTools(
    transport="streamable-http", 
    url=os.getenv("MCP_EXCEL_SERVER_URL", "http://localhost:8017/mcp"), 
    timeout_seconds=int(os.getenv("MCP_TIMEOUT_SECONDS", "60"))
)

# Application lifespan events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events for MongoDB"""
    # Startup
    print("🚀 Starting up application...")
    await mongodb.connect_db()
    yield
    # Shutdown
    print("🛑 Shutting down application...")
    await mongodb.close_db()

# Create ONE agent with MongoDB - it will handle multi-user/multi-session automatically
# When AgentOS calls the agent with user_id and session_id parameters, they will be used
data_analyst_agent = Agent(
    name="Senior Data Analyst Agent",
    model=Gemini(id="gemini-2.5-pro"),
    tools=[code_mcp, excel_mcp],
    db=agno_db,  # Agent uses MongoDB for ALL sessions
    add_history_to_context=True,
    num_history_runs=5,
    read_chat_history=True,  # Load history from MongoDB
    enable_session_summaries=True,
    session_summary_manager=session_summary_manager,
    instructions="""
                    You are a senior data analyst. 
                    You have access to tools that can help you read and analyze Excel files, and write and execute Python code. 
                    Use these tools to answer the user's questions based on the data in the provided Excel file. 
                    You must first read the relevant data from the excel file to understand what columns are available in each sheet and some first rows of data, and how you can use/aggregate this information to answer the user's questions.
                    For complex analysis like grouping, aggregations, filtering based on conditions, merging/joining multiple sheets, always write and execute Python code using pandas (Use run_python_code tool) to ensure accuracy.
                    Always think step-by-step.
                    **IMPORTANT : Note in any Excel sheet you should not read more than 10 rows. Plan efficiently to use minimum information and token usage.**
                    If you want to find unique values in a column you can use pandas python functions etc.
                    You can use Excel MCP Tools and Python Tools
                    It can be a multisheet analysis
                    You must first understand the columns in the relevant sheet and the type of data in each column and make a plan of how to answer the user.
                    After getting relevant data from excel you can use pandas for data modification/ extraction/ group by and aggregation
                """,
    markdown=True
)

# Dependencies
async def get_current_user(request: Request) -> Dict[str, Any]:
    """Dependency to extract current user from request"""
    return await auth_middleware.verify_session(request)

async def get_db():
    """Get MongoDB database instance"""
    return mongodb.get_db()

# Custom FastAPI app with lifespan
app: FastAPI = FastAPI(
    title="Multi-User Agent Application",
    version="2.0.0",
    description="Production-ready multi-user AI agent application",
    lifespan=lifespan
)

# Add CORS middleware
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint (public)
@app.get("/health")
async def health_check():
    """Check application and database health"""
    mongo_health = await mongodb.health_check()
    return {
        "status": "healthy" if mongo_health["ok"] else "unhealthy",
        "database": mongo_health,
        "timestamp": datetime.utcnow().isoformat()
    }

# Pydantic models for request/response
class SignUpRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None

class SignInRequest(BaseModel):
    email: str
    password: str

class AuthResponse(BaseModel):
    user: Dict[str, Any]
    session: Dict[str, Any]

# Authentication endpoints (public)
@app.post("/auth/signup", response_model=AuthResponse)
async def sign_up(request: Request, data: SignUpRequest):
    """Sign up a new user"""
    try:
        # Create user
        user = await auth_service.create_user(
            email=data.email,
            password=data.password,
            name=data.name
        )
        
        # Create session
        session = await auth_service.create_session(
            user_id=user["id"],
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        
        return {
            "user": user,
            "session": session
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sign up failed: {str(e)}")

@app.post("/auth/signin", response_model=AuthResponse)
async def sign_in(request: Request, data: SignInRequest):
    """Sign in an existing user"""
    try:
        # Authenticate user
        user = await auth_service.authenticate_user(
            email=data.email,
            password=data.password
        )
        
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )
        
        # Create session
        session = await auth_service.create_session(
            user_id=user["id"],
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        
        return {
            "user": user,
            "session": session
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sign in failed: {str(e)}")

@app.post("/auth/signout")
async def sign_out(user: Dict[str, Any] = Depends(get_current_user)):
    """Sign out current user"""
    try:
        await auth_service.delete_session(user["session_id"])
        return {"success": True, "message": "Signed out successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sign out failed: {str(e)}")

@app.get("/auth/session")
async def get_session(user: Dict[str, Any] = Depends(get_current_user)):
    """Get current session info"""
    return {
        "user": {
            "id": user["user_id"],
            "email": user["email"],
            "name": user["name"],
            "image": user.get("image"),
            "emailVerified": user.get("email_verified", False)
        }
    }

# Custom route (existing)
@app.post("/customers")
async def get_customers():
    return [
        {
            "id": 1,
            "name": "John Doe",
            "email": "john.doe@example.com",
        },
        {
            "id": 2,
            "name": "Jane Doe",
            "email": "jane.doe@example.com",
        },
    ]

# Setup AgentOS - it will handle user_id and session_id automatically
agent_os = AgentOS(
    description="Multi-user Agent Application with MongoDB",
    agents=[data_analyst_agent],  # Single agent handles all users/sessions
    base_app=app,
)

app = agent_os.get_app()


if __name__ == "__main__":
    """Run your AgentOS.

    With this setup:
    - API docs: http://localhost:7777/docs
    - MongoDB: Connected automatically on startup
    - Authentication: /auth/signup, /auth/signin, /auth/signout
    - Sessions: /sessions (user-scoped)
    """
    agent_os.serve(app="agent_server:app", reload=True)