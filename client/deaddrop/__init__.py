"""
DeadDrop Client SDK - Zero-knowledge agent mailbox
"""

from .crypto import AgentIdentity, DeadDropCrypto, Message, generate_keypair, get_address_from_pubkey
from .client import DeadDropClient

__version__ = "2.0.0"
__all__ = [
    "AgentIdentity",
    "DeadDropCrypto", 
    "DeadDropClient",
    "Message",
    "generate_keypair",
    "get_address_from_pubkey"
]
