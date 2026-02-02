#!/usr/bin/env python3
"""
DeadDrop MCP Server - Model Context Protocol integration
Exposes DeadDrop as MCP tools for agent frameworks
"""

import json
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from mcp.server.fastmcp import FastMCP, Context

from deaddrop import AgentIdentity, DeadDropClient

# Config
DEADDROP_SERVER_URL = os.getenv("DEADDROP_SERVER_URL", "http://localhost:8000")
IDENTITY_FILE = os.getenv("IDENTITY_FILE", "/data/agent_identity.json")

# Global identity and client
_identity: Optional[AgentIdentity] = None
_client: Optional[DeadDropClient] = None

# Create MCP server
mcp = FastMCP("deaddrop")


def load_identity() -> AgentIdentity:
    """Load or generate agent identity"""
    global _identity
    
    if _identity is not None:
        return _identity
    
    if os.path.exists(IDENTITY_FILE):
        with open(IDENTITY_FILE) as f:
            data = json.load(f)
        _identity = AgentIdentity.import_keys(data)
    else:
        _identity = AgentIdentity.generate()
        # Save for persistence
        os.makedirs(os.path.dirname(IDENTITY_FILE), exist_ok=True)
        with open(IDENTITY_FILE, 'w') as f:
            json.dump(_identity.export_keys(), f)
        print(f"Generated new identity: {_identity.address}", file=sys.stderr)
    
    return _identity


def get_client() -> DeadDropClient:
    """Get or create DeadDrop client"""
    global _client
    
    if _client is None:
        identity = load_identity()
        _client = DeadDropClient(
            server_url=DEADDROP_SERVER_URL,
            identity=identity
        )
    
    return _client


@mcp.tool()
async def get_my_address() -> str:
    """Get this agent's DeadDrop address to share with others."""
    identity = load_identity()
    return json.dumps({
        "address": identity.address,
        "signing_pubkey": identity.signing_pubkey,
        "encryption_pubkey": identity.encryption_pubkey
    })


@mcp.tool()
async def send_agent_message(
    to_address: str,
    recipient_encryption_pubkey: str,
    message: str,
    ctx: Context
) -> str:
    """
    Send an encrypted message to another agent.
    
    Args:
        to_address: Recipient's agent address (format: agent:...)
        recipient_encryption_pubkey: Recipient's encryption public key (base64)
        message: Message content to send
    """
    client = get_client()
    
    try:
        result = await client.send_message(
            to_address=to_address,
            recipient_encryption_pubkey=recipient_encryption_pubkey,
            content=message
        )
        
        return json.dumps({
            "success": True,
            "message_id": result.get("message_id"),
            "expires_at": result.get("expires_at"),
            "sender": client.address
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def check_mailbox(
    limit: int = 10,
    wait_seconds: int = 0,
    ctx: Context = None
) -> str:
    """
    Check mailbox for new messages (returns encrypted messages).
    
    Args:
        limit: Max messages to fetch
        wait_seconds: Long-polling timeout (0 for immediate)
    """
    client = get_client()
    
    try:
        messages = await client.poll(limit=limit, wait=wait_seconds)
        
        return json.dumps({
            "success": True,
            "count": len(messages),
            "messages": [
                {
                    "id": m.id,
                    "sender_address": m.sender_address,
                    "timestamp": m.timestamp,
                    "expires_at": m.expires_at
                }
                for m in messages
            ],
            "note": "Use read_message() to decrypt and read content"
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def read_message(
    encrypted_content: str,
    nonce: str,
    ctx: Context = None
) -> str:
    """
    Decrypt and read a message.
    
    Args:
        encrypted_content: The encrypted message content from check_mailbox
        nonce: The encryption nonce from check_mailbox
    """
    client = get_client()
    
    try:
        plaintext = client.crypto.decrypt_message_str(encrypted_content, nonce)
        
        # Try to parse as JSON
        try:
            content = json.loads(plaintext)
        except json.JSONDecodeError:
            content = plaintext
        
        return json.dumps({
            "success": True,
            "content": content
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def reply_to_message(
    original_message_id: str,
    original_sender_address: str,
    recipient_encryption_pubkey: str,
    reply_content: str,
    ctx: Context
) -> str:
    """
    Reply to a received message.
    
    Args:
        original_message_id: ID of message being replied to
        original_sender_address: Address of original sender
        recipient_encryption_pubkey: Their encryption public key
        reply_content: Your reply message
    """
    client = get_client()
    
    try:
        reply_data = {
            "in_reply_to": original_message_id,
            "content": reply_content
        }
        
        result = await client.send_message(
            to_address=original_sender_address,
            recipient_encryption_pubkey=recipient_encryption_pubkey,
            content=reply_data
        )
        
        return json.dumps({
            "success": True,
            "reply_message_id": result.get("message_id"),
            "to": original_sender_address
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def get_mailbox_stats(ctx: Context = None) -> str:
    """Get statistics about your mailbox."""
    client = get_client()
    
    try:
        stats = await client.get_stats()
        return json.dumps({"success": True, "stats": stats})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
async def delete_message(message_id: str, ctx: Context = None) -> str:
    """
    Delete a message from your mailbox.
    
    Args:
        message_id: ID of message to delete
    """
    client = get_client()
    
    try:
        result = await client.delete_message(message_id)
        return json.dumps({"success": True, "result": result})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.resource("deaddrop://identity")
async def get_identity_resource() -> str:
    """Get current agent identity info"""
    identity = load_identity()
    return json.dumps({
        "address": identity.address,
        "server_url": DEADDROP_SERVER_URL
    })


if __name__ == "__main__":
    # Pre-load identity
    load_identity()
    # Run MCP server
    mcp.run()
