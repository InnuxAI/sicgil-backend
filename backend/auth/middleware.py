"""Authentication middleware for FastAPI"""
from fastapi import Request, HTTPException, status
from jose import JWTError, jwt
from typing import Optional, Dict, Any
from backend.database.mongodb import mongodb
import os
from datetime import datetime

SECRET_KEY = os.getenv("BETTER_AUTH_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"

class BetterAuthMiddleware:
    """Middleware to validate Better Auth sessions"""
    
    async def verify_session(self, request: Request) -> Dict[str, Any]:
        """
        Verify session token from cookies or Authorization header
        Returns user data if valid, raises HTTPException if not
        """
        # Try to get session from cookie first (Better Auth default)
        session_token = request.cookies.get("better-auth.session_token")
        
        # If not in cookie, check Authorization header (for API calls)
        if not session_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                session_token = auth_header.split(" ")[1]
        
        if not session_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated. Please log in.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        try:
            # Decode JWT token
            payload = jwt.decode(
                session_token,
                SECRET_KEY,
                algorithms=[ALGORITHM]
            )
            
            user_id: str = payload.get("sub")
            session_id: str = payload.get("session_id")
            
            if user_id is None or session_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials"
                )
            
            # Verify session exists in MongoDB and is not expired
            db = mongodb.get_db()
            session = await db.sessions.find_one({"id": session_id})
            
            if not session:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired or invalid. Please log in again."
                )
            
            # Check if session is expired
            if session.get("expiresAt"):
                expires_at = session["expiresAt"]
                if isinstance(expires_at, datetime) and expires_at < datetime.utcnow():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session expired. Please log in again."
                    )
            
            # Get user data
            user = await db.users.find_one({"id": user_id})
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found"
                )
            
            # Return user context
            return {
                "user_id": user_id,
                "email": user.get("email"),
                "name": user.get("name"),
                "image": user.get("image"),
                "session_id": session_id,
                "email_verified": user.get("emailVerified", False)
            }
            
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {str(e)}"
            )
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Authentication error: {str(e)}"
            )
    
    async def verify_session_optional(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Optional authentication - returns user data if authenticated, None if not
        Useful for endpoints that work with or without authentication
        """
        try:
            return await self.verify_session(request)
        except HTTPException:
            return None
    
    async def check_rate_limit(
        self,
        user_id: str,
        endpoint: str,
        max_requests: int = 100,
        time_window_minutes: int = 60
    ) -> bool:
        """
        Check if user has exceeded rate limit
        Returns True if allowed, False if rate limit exceeded
        """
        try:
            db = mongodb.get_db()
            now = datetime.utcnow()
            
            # Get current date (for daily tracking)
            date_key = now.replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Find or create usage log
            usage_log = await db.api_usage_logs.find_one({
                "userId": user_id,
                "endpoint": endpoint,
                "date": date_key
            })
            
            if not usage_log:
                # Create new log
                await db.api_usage_logs.insert_one({
                    "userId": user_id,
                    "endpoint": endpoint,
                    "requestCount": 1,
                    "date": date_key,
                    "lastRequest": now
                })
                return True
            
            # Check if exceeded limit
            if usage_log["requestCount"] >= max_requests:
                return False
            
            # Increment counter
            await db.api_usage_logs.update_one(
                {
                    "userId": user_id,
                    "endpoint": endpoint,
                    "date": date_key
                },
                {
                    "$inc": {"requestCount": 1},
                    "$set": {"lastRequest": now}
                }
            )
            
            return True
            
        except Exception as e:
            print(f"⚠️ Rate limit check error: {e}")
            return True  # Allow request on error (fail open)

# Global instance
auth_middleware = BetterAuthMiddleware()
