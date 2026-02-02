#!/usr/bin/env python3
"""
DeadDrop Server - Zero-Knowledge Agent Mailbox
FastAPI + Redis Streams with crypto-address authentication
"""

import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("deaddrop")

# Config
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MAX_PAYLOAD_SIZE = int(os.getenv("MAX_PAYLOAD_SIZE", "1048576"))  # 1MB
MESSAGE_TTL = int(os.getenv("MESSAGE_TTL", "86400"))  # 24 hours
MAX_MESSAGES_PER_MAILBOX = int(os.getenv("MAX_MESSAGES_PER_MAILBOX", "1000"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

# Rate limiting storage (in production, use Redis)
_rate_limits: dict[str, list[float]] = {}


class DepositRequest(BaseModel):
    """Request to deposit a message"""
    encrypted_content: str = Field(..., description="Base64 encrypted message content")
    sender_address: str = Field(..., description="Sender's agent address")
    nonce: str = Field(..., description="Encryption nonce")
    
    class Config:
        json_schema_extra = {
            "example": {
                "encrypted_content": "base64encrypted...",
                "sender_address": "agent:a1b2c3d4e5f67890",
                "nonce": "base64nonce..."
            }
        }


class DeadDropMessage(BaseModel):
    """A message in the mailbox"""
    id: str
    sender_address: str
    encrypted_content: str
    nonce: str
    timestamp: float
    expires_at: float


class DeadDropState:
    """Application state with Redis connection"""
    def __init__(self):
        self.redis: Optional[redis.Redis] = None
        
    async def connect(self):
        self.redis = await redis.from_url(REDIS_URL, decode_responses=True)
        logger.info(f"Connected to Redis at {REDIS_URL}")
        
    async def disconnect(self):
        if self.redis:
            await self.redis.close()


state = DeadDropState()


def get_address_from_pubkey(pubkey_hex: str) -> str:
    """Generate agent address from public key: agent:[SHA256(pubkey)[:16]]"""
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    hash_bytes = hashlib.sha256(pubkey_bytes).digest()
    return f"agent:{hash_bytes[:16].hex()}"


def validate_address(address: str) -> bool:
    """Validate agent address format"""
    if not address.startswith("agent:"):
        return False
    hex_part = address[6:]
    if len(hex_part) != 32:  # 16 bytes = 32 hex chars
        return False
    try:
        int(hex_part, 16)
        return True
    except ValueError:
        return False


def check_rate_limit(key: str, limit: int = RATE_LIMIT_PER_MINUTE, window: int = 60) -> bool:
    """Check if request is within rate limit"""
    now = time.time()
    
    if key not in _rate_limits:
        _rate_limits[key] = []
    
    # Remove old entries outside window
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window]
    
    # Check limit
    if len(_rate_limits[key]) >= limit:
        return False
    
    # Add current request
    _rate_limits[key].append(now)
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan"""
    await state.connect()
    yield
    await state.disconnect()


app = FastAPI(
    title="DeadDrop",
    description="Zero-knowledge agent mailbox with crypto-address authentication",
    version="2.0.0",
    lifespan=lifespan
)

# Middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting per IP and path"""
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    
    # IP-based rate limiting
    if not check_rate_limit(f"ip:{client_ip}", limit=RATE_LIMIT_PER_MINUTE * 2):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "retry_after": 60}
        )
    
    # Address-specific rate limiting for mailbox operations
    if path.startswith("/mailbox/") and request.method in ["POST", "GET"]:
        address = path.split("/")[2] if len(path.split("/")) > 2 else None
        if address and not check_rate_limit(f"addr:{address}"):
            return JSONResponse(
                status_code=429,
                content={"error": "Mailbox rate limit exceeded", "retry_after": 60}
            )
    
    response = await call_next(request)
    return response


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        await state.redis.ping()
        return {
            "status": "healthy",
            "redis": "connected",
            "timestamp": time.time()
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis error: {e}")


@app.post("/mailbox/{address}")
async def deposit_message(
    address: str,
    request: DepositRequest,
    req: Request
):
    """
    Deposit an encrypted message into a mailbox.
    
    The server never sees plaintext - only encrypted content and routing info.
    Authentication is implicit via crypto addresses.
    """
    # Validate address format
    if not validate_address(address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    
    # Validate sender address
    if not validate_address(request.sender_address):
        raise HTTPException(status_code=400, detail="Invalid sender address format")
    
    # Check payload size
    payload_size = len(request.encrypted_content.encode())
    if payload_size > MAX_PAYLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large: {payload_size} bytes (max: {MAX_PAYLOAD_SIZE})"
        )
    
    # Generate message ID
    message_id = hashlib.sha256(
        f"{request.sender_address}:{address}:{time.time()}:{os.urandom(16)}".encode()
    ).hexdigest()[:32]
    
    timestamp = time.time()
    expires_at = timestamp + MESSAGE_TTL
    
    # Create message
    message = {
        "id": message_id,
        "sender_address": request.sender_address,
        "encrypted_content": request.encrypted_content,
        "nonce": request.nonce,
        "timestamp": timestamp,
        "expires_at": expires_at
    }
    
    # Store in Redis Stream
    stream_key = f"mailbox:{address}"
    
    # Check mailbox size
    current_size = await state.redis.xlen(stream_key)
    if current_size >= MAX_MESSAGES_PER_MAILBOX:
        # Remove oldest message
        await state.redis.xtrim(stream_key, maxlen=MAX_MESSAGES_PER_MAILBOX - 1)
    
    # Add message to stream
    await state.redis.xadd(
        stream_key,
        message,
        maxlen=MAX_MESSAGES_PER_MAILBOX
    )
    
    # Add to expiry index
    await state.redis.zadd(
        f"expiry:{address}",
        {message_id: expires_at}
    )
    
    logger.info(f"Message {message_id} deposited for {address} from {request.sender_address}")
    
    return {
        "success": True,
        "message_id": message_id,
        "expires_at": expires_at,
        "mailbox_size": current_size + 1
    }


@app.get("/mailbox/{address}")
async def poll_mailbox(
    address: str,
    last_id: str = "0",
    limit: int = 100,
    wait: int = 0
):
    """
    Poll mailbox for messages.
    
    Supports long-polling with 'wait' parameter (seconds).
    Returns encrypted messages - client must decrypt.
    """
    # Validate address
    if not validate_address(address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    
    stream_key = f"mailbox:{address}"
    
    # Clean up expired messages first
    now = time.time()
    expired = await state.redis.zrangebyscore(f"expiry:{address}", 0, now)
    if expired:
        for msg_id in expired:
            # Find and delete from stream (scan for it)
            messages = await state.redis.xrange(stream_key)
            for entry_id, entry_data in messages:
                if entry_data.get("id") == msg_id:
                    await state.redis.xdel(stream_key, entry_id)
                    break
        await state.redis.zrem(f"expiry:{address}", *expired)
    
    # Read messages
    try:
        response = await state.redis.xread(
            {stream_key: last_id},
            count=limit,
            block=wait * 1000 if wait > 0 else None
        )
        
        messages = []
        if response:
            for stream_name, entries in response:
                for entry_id, entry_data in entries:
                    # Check if expired
                    expires_at = float(entry_data.get("expires_at", 0))
                    if expires_at > now:
                        messages.append({
                            "id": entry_data.get("id"),
                            "sender_address": entry_data.get("sender_address"),
                            "encrypted_content": entry_data.get("encrypted_content"),
                            "nonce": entry_data.get("nonce"),
                            "timestamp": float(entry_data.get("timestamp")),
                            "expires_at": expires_at
                        })
        
        return {
            "success": True,
            "address": address,
            "messages": messages,
            "count": len(messages),
            "has_more": len(messages) == limit
        }
        
    except Exception as e:
        logger.error(f"Error polling mailbox: {e}")
        raise HTTPException(status_code=500, detail="Error polling mailbox")


@app.delete("/mailbox/{address}/{message_id}")
async def delete_message(address: str, message_id: str):
    """Delete a specific message from mailbox"""
    if not validate_address(address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    
    stream_key = f"mailbox:{address}"
    
    # Find message in stream
    messages = await state.redis.xrange(stream_key)
    deleted = False
    
    for entry_id, entry_data in messages:
        if entry_data.get("id") == message_id:
            await state.redis.xdel(stream_key, entry_id)
            await state.redis.zrem(f"expiry:{address}", message_id)
            deleted = True
            break
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Message not found")
    
    return {
        "success": True,
        "deleted": message_id
    }


@app.get("/stats/{address}")
async def get_stats(address: str):
    """Get mailbox statistics"""
    if not validate_address(address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    
    stream_key = f"mailbox:{address}"
    expiry_key = f"expiry:{address}"
    
    total = await state.redis.xlen(stream_key)
    now = time.time()
    
    # Count valid (non-expired) messages
    valid = await state.redis.zcount(expiry_key, now, "+inf")
    expired = await state.redis.zcount(expiry_key, "-inf", now)
    
    return {
        "address": address,
        "total_messages": total,
        "valid_messages": valid,
        "expired_messages": expired,
        "capacity_used": total / MAX_MESSAGES_PER_MAILBOX,
        "timestamp": now
    }


@app.post("/cleanup/{address}")
async def cleanup_expired(address: str):
    """Manually trigger cleanup of expired messages"""
    if not validate_address(address):
        raise HTTPException(status_code=400, detail="Invalid address format")
    
    stream_key = f"mailbox:{address}"
    expiry_key = f"expiry:{address}"
    now = time.time()
    
    # Get expired message IDs
    expired = await state.redis.zrangebyscore(expiry_key, 0, now)
    cleaned = 0
    
    for msg_id in expired:
        messages = await state.redis.xrange(stream_key)
        for entry_id, entry_data in messages:
            if entry_data.get("id") == msg_id:
                await state.redis.xdel(stream_key, entry_id)
                cleaned += 1
                break
    
    if expired:
        await state.redis.zrem(expiry_key, *expired)
    
    return {
        "success": True,
        "cleaned": cleaned,
        "address": address
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
