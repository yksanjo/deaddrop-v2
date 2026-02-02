"""
DeadDrop Client - Async HTTP client for the mailbox server
"""

import asyncio
import json
import logging
from typing import AsyncIterator, Callable, List, Optional

import httpx

from .crypto import AgentIdentity, DeadDropCrypto, Message

logger = logging.getLogger("deaddrop.client")


class DeadDropClient:
    """
    Async client for DeadDrop mailbox server.
    
    Provides HTTP polling, message encryption/decryption, and message handling.
    """
    
    def __init__(
        self,
        server_url: str,
        identity: AgentIdentity,
        poll_interval: float = 5.0,
        timeout: float = 30.0
    ):
        """
        Initialize DeadDrop client.
        
        Args:
            server_url: DeadDrop server URL (e.g., "http://localhost:8000")
            identity: AgentIdentity with keys and address
            poll_interval: Seconds between poll requests
            timeout: HTTP request timeout
        """
        self.server_url = server_url.rstrip("/")
        self.identity = identity
        self.crypto = DeadDropCrypto(identity)
        self.poll_interval = poll_interval
        self.timeout = timeout
        
        self._client: Optional[httpx.AsyncClient] = None
        self._running = False
        self._message_handlers: List[Callable[[Message], None]] = []
        self._last_poll_id = "0"
        self._recipient_keys: dict[str, str] = {}  # address -> encryption_pubkey cache
    
    @property
    def address(self) -> str:
        """Get this agent's address"""
        return self.identity.address
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )
        return self._client
    
    async def close(self):
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def send_message(
        self,
        to_address: str,
        recipient_encryption_pubkey: str,
        content: bytes | str | dict
    ) -> dict:
        """
        Send an encrypted message to another agent.
        
        Args:
            to_address: Recipient's agent address (agent:...)
            recipient_encryption_pubkey: Recipient's X25519 public key (base64)
            content: Message content (bytes, string, or dict)
            
        Returns:
            Server response with message_id
        """
        client = await self._get_client()
        
        # Serialize content
        if isinstance(content, dict):
            content = json.dumps(content)
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        # Encrypt
        encrypted_content, nonce = self.crypto.encrypt_message(
            recipient_encryption_pubkey,
            content
        )
        
        # Send to server
        response = await client.post(
            f"{self.server_url}/mailbox/{to_address}",
            json={
                "encrypted_content": encrypted_content,
                "sender_address": self.address,
                "nonce": nonce
            }
        )
        response.raise_for_status()
        
        # Cache recipient key
        self._recipient_keys[to_address] = recipient_encryption_pubkey
        
        return response.json()
    
    async def quick_send(
        self,
        to_address: str,
        content: bytes | str | dict
    ) -> dict:
        """
        Send message using cached recipient key.
        
        Raises:
            KeyError: If recipient key not in cache
        """
        if to_address not in self._recipient_keys:
            raise KeyError(f"No cached encryption key for {to_address}. "
                          f"Use send_message() with explicit key first.")
        
        return await self.send_message(
            to_address,
            self._recipient_keys[to_address],
            content
        )
    
    async def poll(
        self,
        last_id: str = "0",
        limit: int = 100,
        wait: int = 0
    ) -> List[Message]:
        """
        Poll mailbox for messages.
        
        Args:
            last_id: Last message ID received
            limit: Max messages to fetch
            wait: Long-polling timeout in seconds
            
        Returns:
            List of encrypted Message objects
        """
        client = await self._get_client()
        
        response = await client.get(
            f"{self.server_url}/mailbox/{self.address}",
            params={
                "last_id": last_id,
                "limit": limit,
                "wait": wait
            }
        )
        response.raise_for_status()
        
        data = response.json()
        messages = []
        
        for msg_data in data.get("messages", []):
            message = Message(
                id=msg_data["id"],
                sender_address=msg_data["sender_address"],
                encrypted_content=msg_data["encrypted_content"],
                nonce=msg_data["nonce"],
                timestamp=msg_data["timestamp"],
                expires_at=msg_data["expires_at"]
            )
            messages.append(message)
        
        return messages
    
    async def poll_and_decrypt(
        self,
        last_id: str = "0",
        limit: int = 100,
        wait: int = 0
    ) -> List[Message]:
        """
        Poll for messages and automatically decrypt them.
        
        Returns:
            List of decrypted Message objects
        """
        messages = await self.poll(last_id, limit, wait)
        
        for message in messages:
            try:
                plaintext = self.crypto.decrypt_message(
                    message.encrypted_content,
                    message.nonce
                )
                message.content = plaintext
            except Exception as e:
                logger.error(f"Failed to decrypt message {message.id}: {e}")
                message.content = b""
        
        return messages
    
    async def delete_message(self, message_id: str) -> dict:
        """Delete a message from mailbox"""
        client = await self._get_client()
        response = await client.delete(
            f"{self.server_url}/mailbox/{self.address}/{message_id}"
        )
        response.raise_for_status()
        return response.json()
    
    async def get_stats(self) -> dict:
        """Get mailbox statistics"""
        client = await self._get_client()
        response = await client.get(
            f"{self.server_url}/stats/{self.address}"
        )
        response.raise_for_status()
        return response.json()
    
    async def cleanup(self) -> dict:
        """Trigger cleanup of expired messages"""
        client = await self._get_client()
        response = await client.post(
            f"{self.server_url}/cleanup/{self.address}"
        )
        response.raise_for_status()
        return response.json()
    
    def on_message(self, handler: Callable[[Message], None]):
        """Register a message handler callback"""
        self._message_handlers.append(handler)
        return handler
    
    async def start_polling(self, auto_decrypt: bool = True):
        """Start background polling loop"""
        self._running = True
        logger.info(f"Starting polling loop for {self.address}")
        
        while self._running:
            try:
                if auto_decrypt:
                    messages = await self.poll_and_decrypt(
                        last_id=self._last_poll_id,
                        wait=30
                    )
                else:
                    messages = await self.poll(
                        last_id=self._last_poll_id,
                        wait=30
                    )
                
                for message in messages:
                    self._last_poll_id = message.id
                    
                    # Notify handlers
                    for handler in self._message_handlers:
                        try:
                            if asyncio.iscoroutinefunction(handler):
                                await handler(message)
                            else:
                                handler(message)
                        except Exception as e:
                            logger.error(f"Handler error: {e}")
                
                # Short delay if no messages
                if not messages:
                    await asyncio.sleep(self.poll_interval)
                    
            except Exception as e:
                logger.error(f"Polling error: {e}")
                await asyncio.sleep(self.poll_interval)
    
    def stop_polling(self):
        """Stop background polling"""
        self._running = False
    
    async def reply_to(
        self,
        message: Message,
        content: bytes | str | dict,
        recipient_encryption_pubkey: Optional[str] = None
    ) -> dict:
        """
        Reply to a received message.
        
        Args:
            message: Original message to reply to
            content: Reply content
            recipient_encryption_pubkey: Optional explicit key (uses cached if not provided)
        """
        # Create reply with reference
        if isinstance(content, dict):
            reply_data = {
                "in_reply_to": message.id,
                "original_sender": message.sender_address,
                "content": content
            }
        else:
            reply_data = {
                "in_reply_to": message.id,
                "original_sender": message.sender_address,
                "content": content.decode('utf-8') if isinstance(content, bytes) else content
            }
        
        # Get recipient key
        pubkey = recipient_encryption_pubkey
        if pubkey is None:
            if message.sender_address in self._recipient_keys:
                pubkey = self._recipient_keys[message.sender_address]
            else:
                raise KeyError(f"No encryption key for {message.sender_address}")
        
        return await self.send_message(
            message.sender_address,
            pubkey,
            reply_data
        )
    
    async def acknowledge(self, message: Message) -> dict:
        """Send an acknowledgment for a received message"""
        ack_data = {
            "type": "ack",
            "message_id": message.id,
            "received_at": asyncio.get_event_loop().time()
        }
        
        return await self.reply_to(message, ack_data)
    
    async def wait_for_message(
        self,
        timeout: float = 60.0,
        filter_fn: Optional[Callable[[Message], bool]] = None
    ) -> Optional[Message]:
        """
        Wait for a specific message matching filter.
        
        Args:
            timeout: Max time to wait
            filter_fn: Optional filter function(message) -> bool
            
        Returns:
            Matching message or None if timeout
        """
        start = asyncio.get_event_loop().time()
        
        while asyncio.get_event_loop().time() - start < timeout:
            messages = await self.poll_and_decrypt(
                last_id=self._last_poll_id,
                wait=min(30, timeout)
            )
            
            for message in messages:
                self._last_poll_id = message.id
                
                if filter_fn is None or filter_fn(message):
                    return message
            
            if not messages:
                await asyncio.sleep(1)
        
        return None
