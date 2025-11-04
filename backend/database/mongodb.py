"""MongoDB connection and database management"""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
import os
from datetime import datetime

class MongoDB:
    """MongoDB connection manager using Motor (async driver)"""
    
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    
    @classmethod
    async def connect_db(cls):
        """Connect to MongoDB and create indexes"""
        mongodb_url = os.getenv(
            "MONGODB_URL",
            "mongodb://localhost:27017"
        )
        db_name = os.getenv("MONGODB_DB_NAME", "agentdb")
        
        try:
            cls.client = AsyncIOMotorClient(
                mongodb_url,
                serverSelectionTimeoutMS=5000
            )
            cls.db = cls.client[db_name]
            
            # Test connection
            await cls.client.admin.command('ping')
            
            # Create indexes
            await cls._create_indexes()
            
            print(f"✅ Connected to MongoDB: {db_name}")
            print(f"📍 URL: {mongodb_url[:20]}...")
        except Exception as e:
            print(f"❌ Failed to connect to MongoDB: {e}")
            raise
    
    @classmethod
    async def close_db(cls):
        """Close MongoDB connection"""
        if cls.client:
            cls.client.close()
            print("❌ MongoDB connection closed")
    
    @classmethod
    async def _create_indexes(cls):
        """Create necessary indexes for all collections"""
        if cls.db is None:
            return
        
        try:
            # Users collection (Better Auth managed)
            await cls.db.users.create_index("email", unique=True)
            await cls.db.users.create_index("id", unique=True)
            
            # Sessions collection (Better Auth managed)
            await cls.db.sessions.create_index("userId")
            await cls.db.sessions.create_index("id", unique=True)
            await cls.db.sessions.create_index(
                "expiresAt",
                expireAfterSeconds=0  # Auto-delete expired sessions
            )
            
            # Accounts collection (OAuth providers)
            await cls.db.accounts.create_index("userId")
            await cls.db.accounts.create_index(
                [("provider", 1), ("providerAccountId", 1)],
                unique=True
            )
            
            # Verification tokens (Email verification)
            await cls.db.verification_tokens.create_index("token", unique=True)
            await cls.db.verification_tokens.create_index(
                "expires",
                expireAfterSeconds=0
            )
            
            # Agent sessions collection (Managed by Agno - DO NOT create indexes here)
            # Agno manages this collection and creates indexes automatically
            # We removed custom indexes to prevent conflicts with Agno's schema
            
            # User preferences
            await cls.db.user_preferences.create_index("userId", unique=True)
            
            # API usage logs (for rate limiting)
            await cls.db.api_usage_logs.create_index(
                [("userId", 1), ("endpoint", 1), ("date", 1)],
                unique=True
            )
            await cls.db.api_usage_logs.create_index(
                "date",
                expireAfterSeconds=2592000  # Auto-delete after 30 days
            )
            
            print("✅ MongoDB indexes created successfully")
        except Exception as e:
            print(f"⚠️ Warning: Error creating indexes: {e}")
    
    @classmethod
    def get_db(cls) -> AsyncIOMotorDatabase:
        """Get database instance"""
        if cls.db is None:
            raise Exception("Database not connected. Call connect_db() first.")
        return cls.db
    
    @classmethod
    async def health_check(cls) -> dict:
        """Check MongoDB connection health"""
        try:
            if cls.client is None:
                return {"status": "disconnected", "error": "No client connection"}
            
            await cls.client.admin.command('ping')
            
            # Get database stats
            stats = await cls.db.command("dbStats")
            
            return {
                "status": "connected",
                "database": cls.db.name,
                "collections": stats.get("collections", 0),
                "dataSize": stats.get("dataSize", 0),
                "ok": True
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "ok": False
            }

# Global instance
mongodb = MongoDB()
