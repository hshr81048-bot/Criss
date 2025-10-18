from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
from emergentintegrations.llm.chat import LlmChat, UserMessage
import bcrypt
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')

# Define Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str

class AuthResponse(BaseModel):
    token: str
    username: str
class Message(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    conversation_id: str
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Conversation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ConversationCreate(BaseModel):
    title: Optional[str] = "Yeni Konuşma"

class MessageCreate(BaseModel):
    conversation_id: str
    content: str

class ChatResponse(BaseModel):
    user_message: Message
    assistant_message: Message

# Routes
@api_router.get("/")
async def root():
    return {"message": "ZahirAI Backend Running"}

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, username: str) -> str:
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.now(timezone.utc).timestamp() + 86400 * 7  # 7 days
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    return verify_token(credentials.credentials)

# Auth endpoints
@api_router.post("/auth/register", response_model=AuthResponse)
async def register(input: RegisterRequest):
    # Check if user exists
    existing_user = await db.users.find_one({"username": input.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    user = User(
        username=input.username,
        password_hash=hash_password(input.password)
    )
    doc = user.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.users.insert_one(doc)
    
    # Create token
    token = create_token(user.id, user.username)
    return AuthResponse(token=token, username=user.username)

@api_router.post("/auth/login", response_model=AuthResponse)
async def login(input: LoginRequest):
    # Find user
    user = await db.users.find_one({"username": input.username})
    if not user or not verify_password(input.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create token
    token = create_token(user['id'], user['username'])
    return AuthResponse(token=token, username=user['username'])

# Conversation endpoints
@api_router.post("/conversations", response_model=Conversation)
async def create_conversation(input: ConversationCreate, current_user: dict = Depends(get_current_user)):
    conversation = Conversation(title=input.title)
    doc = conversation.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    doc['user_id'] = current_user['user_id']
    await db.conversations.insert_one(doc)
    return conversation

@api_router.get("/conversations", response_model=List[Conversation])
async def get_conversations(current_user: dict = Depends(get_current_user)):
    conversations = await db.conversations.find(
        {"user_id": current_user['user_id']}, 
        {"_id": 0}
    ).sort("updated_at", -1).to_list(100)
    for conv in conversations:
        if isinstance(conv['created_at'], str):
            conv['created_at'] = datetime.fromisoformat(conv['created_at'])
        if isinstance(conv['updated_at'], str):
            conv['updated_at'] = datetime.fromisoformat(conv['updated_at'])
    return conversations

@api_router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str, current_user: dict = Depends(get_current_user)):
    # Delete conversation and all its messages
    await db.conversations.delete_one({"id": conversation_id, "user_id": current_user['user_id']})
    await db.messages.delete_many({"conversation_id": conversation_id})
    return {"message": "Conversation deleted"}

# Message endpoints
@api_router.get("/conversations/{conversation_id}/messages", response_model=List[Message])
async def get_messages(conversation_id: str, current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find(
        {"conversation_id": conversation_id}, 
        {"_id": 0}
    ).sort("timestamp", 1).to_list(1000)
    
    for msg in messages:
        if isinstance(msg['timestamp'], str):
            msg['timestamp'] = datetime.fromisoformat(msg['timestamp'])
    return messages

@api_router.post("/chat", response_model=ChatResponse)
async def chat(input: MessageCreate, current_user: dict = Depends(get_current_user)):
    try:
        # Save user message
        user_message = Message(
            conversation_id=input.conversation_id,
            role="user",
            content=input.content
        )
        user_doc = user_message.model_dump()
        user_doc['timestamp'] = user_doc['timestamp'].isoformat()
        await db.messages.insert_one(user_doc)
        
        # Get conversation history
        messages = await db.messages.find(
            {"conversation_id": input.conversation_id},
            {"_id": 0}
        ).sort("timestamp", 1).to_list(1000)
        
        # Initialize LlmChat with Emergent key
        api_key = os.environ.get('EMERGENT_LLM_KEY')
        chat_client = LlmChat(
            api_key=api_key,
            session_id=input.conversation_id,
            system_message="Sen ZahirAI'sın, yardımsever ve akıllı bir yapay zeka asistanısın. Kullanıcılara Türkçe olarak yardımcı oluyorsun."
        ).with_model("openai", "gpt-4o")
        
        # Send message to AI
        user_msg = UserMessage(text=input.content)
        ai_response = await chat_client.send_message(user_msg)
        
        # Save assistant message
        assistant_message = Message(
            conversation_id=input.conversation_id,
            role="assistant",
            content=ai_response
        )
        assistant_doc = assistant_message.model_dump()
        assistant_doc['timestamp'] = assistant_doc['timestamp'].isoformat()
        await db.messages.insert_one(assistant_doc)
        
        # Update conversation title if it's the first message
        if len(messages) == 0:
            # Generate a title from the first user message (first 50 chars)
            title = input.content[:50] + "..." if len(input.content) > 50 else input.content
            await db.conversations.update_one(
                {"id": input.conversation_id},
                {"$set": {
                    "title": title,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }}
            )
        else:
            # Just update the timestamp
            await db.conversations.update_one(
                {"id": input.conversation_id},
                {"$set": {"updated_at": datetime.now(timezone.utc).isoformat()}}
            )
        
        return ChatResponse(
            user_message=user_message,
            assistant_message=assistant_message
        )
    except Exception as e:
        logging.error(f"Chat error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
