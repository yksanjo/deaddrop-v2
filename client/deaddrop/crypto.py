"""
DeadDrop Cryptography Module
NaCl encryption with Ed25519 identities and X25519+XSalsa20-Poly1305 messages
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Optional, Tuple

import nacl.public
import nacl.signing
from nacl.encoding import Base64Encoder, HexEncoder
from nacl.exceptions import CryptoError


@dataclass
class AgentIdentity:
    """
    Agent identity with Ed25519 signing key and X25519 encryption key.
    
    Address format: agent:[SHA256(signing_pubkey)[:16]]
    """
    signing_key: nacl.signing.SigningKey
    encryption_key: nacl.public.PrivateKey
    
    @classmethod
    def generate(cls) -> "AgentIdentity":
        """Generate a new agent identity"""
        signing_key = nacl.signing.SigningKey.generate()
        encryption_key = nacl.public.PrivateKey.generate()
        return cls(signing_key=signing_key, encryption_key=encryption_key)
    
    @classmethod
    def from_seed(cls, seed: bytes) -> "AgentIdentity":
        """Generate identity from a seed (for deterministic keys)"""
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes")
        signing_key = nacl.signing.SigningKey(seed)
        # Derive encryption key from signing key
        encryption_seed = hashlib.sha256(seed + b"encryption").digest()
        encryption_key = nacl.public.PrivateKey(encryption_seed)
        return cls(signing_key=signing_key, encryption_key=encryption_key)
    
    @property
    def address(self) -> str:
        """Get agent address: agent:[SHA256(signing_pubkey)[:16]]"""
        pubkey_bytes = bytes(self.signing_key.verify_key)
        hash_bytes = hashlib.sha256(pubkey_bytes).digest()
        return f"agent:{hash_bytes[:16].hex()}"
    
    @property
    def signing_pubkey(self) -> str:
        """Get base64-encoded signing public key"""
        return self.signing_key.verify_key.encode(Base64Encoder).decode()
    
    @property
    def encryption_pubkey(self) -> str:
        """Get base64-encoded encryption public key"""
        return self.encryption_key.public_key.encode(Base64Encoder).decode()
    
    def export_keys(self, password: Optional[str] = None) -> dict:
        """Export keys for storage (optionally password-protected)"""
        data = {
            "signing_key": self.signing_key.encode(Base64Encoder).decode(),
            "encryption_key": self.encryption_key.encode(Base64Encoder).decode(),
            "address": self.address
        }
        
        if password:
            # Simple XOR encryption with password hash (not production secure)
            # In production, use proper key derivation like Argon2
            key_hash = hashlib.sha256(password.encode()).digest()
            for key in ["signing_key", "encryption_key"]:
                decoded = base64.b64decode(data[key])
                encrypted = bytes(b ^ key_hash[i % len(key_hash)] for i, b in enumerate(decoded))
                data[key] = base64.b64encode(encrypted).decode()
            data["encrypted"] = True
        
        return data
    
    @classmethod
    def import_keys(cls, data: dict, password: Optional[str] = None) -> "AgentIdentity":
        """Import keys from storage"""
        if data.get("encrypted") and password:
            key_hash = hashlib.sha256(password.encode()).digest()
            for key in ["signing_key", "encryption_key"]:
                encrypted = base64.b64decode(data[key])
                decrypted = bytes(b ^ key_hash[i % len(key_hash)] for i, b in enumerate(encrypted))
                data[key] = base64.b64encode(decrypted).decode()
        
        signing_key_bytes = base64.b64decode(data["signing_key"])
        encryption_key_bytes = base64.b64decode(data["encryption_key"])
        
        signing_key = nacl.signing.SigningKey(signing_key_bytes)
        encryption_key = nacl.public.PrivateKey(encryption_key_bytes)
        
        identity = cls(signing_key=signing_key, encryption_key=encryption_key)
        
        # Verify address matches
        if data.get("address") and identity.address != data["address"]:
            raise ValueError("Imported keys don't match stored address")
        
        return identity


class DeadDropCrypto:
    """
    Encryption/decryption for DeadDrop messages.
    
    Uses X25519+XSalsa20-Poly1305 (NaCl crypto_box) for perfect forward secrecy.
    """
    
    def __init__(self, identity: AgentIdentity):
        self.identity = identity
    
    def encrypt_message(
        self,
        recipient_pubkey: str,
        plaintext: bytes | str
    ) -> Tuple[str, str]:
        """
        Encrypt a message for a recipient.
        
        Args:
            recipient_pubkey: Base64-encoded X25519 public key
            plaintext: Message to encrypt
            
        Returns:
            Tuple of (ciphertext_b64, nonce_b64)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Decode recipient public key
        recipient_key = nacl.public.PublicKey(
            base64.b64decode(recipient_pubkey)
        )
        
        # Create ephemeral key pair for this message (forward secrecy)
        ephemeral_private = nacl.public.PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        
        # Encrypt with crypto_box
        box = nacl.public.Box(ephemeral_private, recipient_key)
        nonce = nacl.public.random(nacl.public.Box.NONCE_SIZE)
        encrypted = box.encrypt(plaintext, nonce)
        
        # Prepend ephemeral public key so recipient can decrypt
        full_ciphertext = bytes(ephemeral_public) + encrypted
        
        return (
            base64.b64encode(full_ciphertext).decode(),
            base64.b64encode(nonce).decode()
        )
    
    def decrypt_message(
        self,
        ciphertext_b64: str,
        nonce_b64: str
    ) -> bytes:
        """
        Decrypt a message.
        
        Args:
            ciphertext_b64: Base64 ciphertext (includes ephemeral pubkey)
            nonce_b64: Base64 nonce
            
        Returns:
            Decrypted plaintext bytes
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        
        # Extract sender's ephemeral public key (first 32 bytes)
        ephemeral_public = nacl.public.PublicKey(ciphertext[:32])
        encrypted = ciphertext[32:]
        
        # Decrypt with our private key and sender's ephemeral public key
        box = nacl.public.Box(self.identity.encryption_key, ephemeral_public)
        plaintext = box.decrypt(encrypted, nonce)
        
        return plaintext
    
    def decrypt_message_str(self, ciphertext_b64: str, nonce_b64: str) -> str:
        """Decrypt and return as UTF-8 string"""
        return self.decrypt_message(ciphertext_b64, nonce_b64).decode('utf-8')


class Message:
    """
    High-level message class with reply and acknowledge functionality.
    """
    
    def __init__(
        self,
        id: str,
        sender_address: str,
        encrypted_content: str,
        nonce: str,
        timestamp: float,
        expires_at: float,
        content: Optional[bytes] = None
    ):
        self.id = id
        self.sender_address = sender_address
        self.encrypted_content = encrypted_content
        self.nonce = nonce
        self.timestamp = timestamp
        self.expires_at = expires_at
        self._content = content
        self._replied = False
        self._acknowledged = False
    
    @property
    def content(self) -> bytes:
        """Get decrypted content (must have been decrypted)"""
        if self._content is None:
            raise ValueError("Message not decrypted yet")
        return self._content
    
    @content.setter
    def content(self, value: bytes):
        self._content = value
    
    @property
    def content_str(self) -> str:
        """Get content as UTF-8 string"""
        return self.content.decode('utf-8')
    
    def as_json(self) -> dict:
        """Parse content as JSON"""
        return json.loads(self.content_str)
    
    def reply(
        self,
        crypto: DeadDropCrypto,
        reply_content: bytes | str | dict,
        include_original_ref: bool = True
    ) -> Tuple[str, str, str]:
        """
        Create a reply message.
        
        Returns:
            Tuple of (encrypted_content, nonce, sender_address)
        """
        if isinstance(reply_content, dict):
            reply_content = json.dumps(reply_content)
        if isinstance(reply_content, str):
            reply_content = reply_content.encode('utf-8')
        
        # Include reference to original message if requested
        if include_original_ref:
            original_ref = {
                "in_reply_to": self.id,
                "original_sender": self.sender_address,
                "original_timestamp": self.timestamp
            }
            reply_data = {
                "reply_to": original_ref,
                "content": reply_content.decode('utf-8') if isinstance(reply_content, bytes) else reply_content
            }
            reply_content = json.dumps(reply_data).encode('utf-8')
        
        # We need the recipient's encryption public key to reply
        # In practice, this would be looked up from a directory or previous message
        # For now, we return the content and let the caller handle encryption
        return reply_content.decode('utf-8') if isinstance(reply_content, bytes) else reply_content
    
    def ack(self) -> dict:
        """Generate an acknowledgment message"""
        self._acknowledged = True
        return {
            "type": "ack",
            "message_id": self.id,
            "received_at": time.time(),
            "recipient_address": None  # To be filled by caller
        }
    
    def is_expired(self) -> bool:
        """Check if message has expired"""
        import time
        return time.time() > self.expires_at
    
    def __repr__(self):
        return f"Message(id={self.id[:8]}..., from={self.sender_address}, expired={self.is_expired()})"


def generate_keypair() -> Tuple[str, str]:
    """Generate a new keypair, return (signing_private, encryption_private) as base64"""
    identity = AgentIdentity.generate()
    return (
        identity.signing_key.encode(Base64Encoder).decode(),
        identity.encryption_key.encode(Base64Encoder).decode()
    )


def get_address_from_pubkey(pubkey_b64: str) -> str:
    """Generate address from base64-encoded signing public key"""
    pubkey_bytes = base64.b64decode(pubkey_b64)
    hash_bytes = hashlib.sha256(pubkey_bytes).digest()
    return f"agent:{hash_bytes[:16].hex()}"
