"""Better Auth integration for FastAPI backend"""
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from jose import jwt
from backend.database.mongodb import mongodb

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("BETTER_AUTH_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7

class AuthService:
    """Authentication service for user management"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        return encoded_jwt
    
    @staticmethod
    async def create_user(email: str, password: str, name: Optional[str] = None) -> Dict[str, Any]:
        """Create a new user"""
        from uuid import uuid4
        
        db = mongodb.get_db()
        
        # Check if user already exists
        existing_user = await db.users.find_one({"email": email})
        if existing_user:
            raise ValueError("User with this email already exists")
        
        # Create user
        user_id = f"user_{uuid4().hex}"
        hashed_password = AuthService.hash_password(password)
        
        user_doc = {
            "id": user_id,
            "email": email,
            "name": name or email.split("@")[0],
            "emailVerified": False,
            "image": None,
            "hashedPassword": hashed_password,
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        await db.users.insert_one(user_doc)
        
        # Remove sensitive data
        user_doc.pop("hashedPassword")
        user_doc.pop("_id")
        
        return user_doc
    
    @staticmethod
    async def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user"""
        db = mongodb.get_db()
        
        user = await db.users.find_one({"email": email})
        if not user:
            return None
        
        if not AuthService.verify_password(password, user.get("hashedPassword", "")):
            return None
        
        # Remove sensitive data
        user.pop("hashedPassword", None)
        user.pop("_id", None)
        
        return user
    
    @staticmethod
    async def create_session(user_id: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Dict[str, Any]:
        """Create a new session for a user"""
        from uuid import uuid4
        
        db = mongodb.get_db()
        
        session_id = f"session_{uuid4().hex}"
        expires_at = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
        
        session_doc = {
            "id": session_id,
            "userId": user_id,
            "expiresAt": expires_at,
            "ipAddress": ip_address,
            "userAgent": user_agent,
            "createdAt": datetime.utcnow()
        }
        
        await db.sessions.insert_one(session_doc)
        
        # Create JWT token
        token = AuthService.create_access_token(
            data={
                "sub": user_id,
                "session_id": session_id
            },
            expires_delta=timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
        )
        
        return {
            "session_id": session_id,
            "token": token,
            "expires_at": expires_at.isoformat()
        }
    
    @staticmethod
    async def delete_session(session_id: str):
        """Delete a session (logout)"""
        db = mongodb.get_db()
        await db.sessions.delete_one({"id": session_id})

auth_service = AuthService()
