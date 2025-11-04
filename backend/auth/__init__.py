"""Authentication package initialization"""
from .middleware import auth_middleware, BetterAuthMiddleware

__all__ = ["auth_middleware", "BetterAuthMiddleware"]
