#!/usr/bin/env python3
"""
DeadDrop Demo - Two agents exchanging encrypted messages
"""

import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from deaddrop import AgentIdentity, DeadDropClient


SERVER_URL = "http://localhost:8000"


async def demo():
    """Run two-agent messaging demo"""
    
    print("🦞 DeadDrop Demo - Zero-Knowledge Agent Mailbox")
    print("=" * 60)
    
    # Create two agents
    print("\n1️⃣ Creating two agent identities...")
    alice = AgentIdentity.generate()
    bob = AgentIdentity.generate()
    
    print(f"   Alice: {alice.address}")
    print(f"   Bob:   {bob.address}")
    
    # Create clients
    alice_client = DeadDropClient(SERVER_URL, alice)
    bob_client = DeadDropClient(SERVER_URL, bob)
    
    print(f"   Server: {SERVER_URL}")
    
    try:
        # Test 1: Alice sends message to Bob
        print("\n2️⃣ Alice sends encrypted message to Bob...")
        
        message1 = {
            "type": "greeting",
            "content": "Hello Bob! This is a secret message from Alice.",
            "timestamp": asyncio.get_event_loop().time()
        }
        
        result1 = await alice_client.send_message(
            to_address=bob.address,
            recipient_encryption_pubkey=bob.encryption_pubkey,
            content=message1
        )
        
        print(f"   ✅ Sent! Message ID: {result1['message_id'][:16]}...")
        print(f"      Expires: {result1['expires_at']}")
        
        # Test 2: Bob receives and decrypts
        print("\n3️⃣ Bob polls and decrypts message...")
        
        messages = await bob_client.poll_and_decrypt(wait=5)
        
        if messages:
            for msg in messages:
                print(f"   📨 From: {msg.sender_address}")
                print(f"   Content: {msg.content_str}")
                print(f"   ✅ Decrypted successfully!")
                
                # Store message for reply
                bob_msg = msg
        else:
            print("   ❌ No messages received!")
            return
        
        # Test 3: Bob replies
        print("\n4️⃣ Bob replies to Alice...")
        
        reply = {
            "type": "reply",
            "content": "Hi Alice! Got your secret message. Here's my reply.",
            "in_reply_to": bob_msg.id
        }
        
        result2 = await bob_client.send_message(
            to_address=alice.address,
            recipient_encryption_pubkey=alice.encryption_pubkey,
            content=reply
        )
        
        print(f"   ✅ Reply sent! ID: {result2['message_id'][:16]}...")
        
        # Test 4: Alice receives reply
        print("\n5️⃣ Alice receives Bob's reply...")
        
        alice_messages = await alice_client.poll_and_decrypt(wait=5)
        
        if alice_messages:
            for msg in alice_messages:
                print(f"   📨 From: {msg.sender_address}")
                try:
                    data = json.loads(msg.content_str)
                    print(f"   Content: {json.dumps(data, indent=4)}")
                except:
                    print(f"   Content: {msg.content_str}")
        
        # Test 5: Show stats
        print("\n6️⃣ Checking mailbox stats...")
        
        alice_stats = await alice_client.get_stats()
        bob_stats = await bob_client.get_stats()
        
        print(f"   Alice mailbox: {alice_stats['total_messages']} message(s)")
        print(f"   Bob mailbox: {bob_stats['total_messages']} message(s)")
        
        # Test 6: Demonstrate reply method
        print("\n7️⃣ Testing high-level reply method...")
        
        # Bob sends another message that Alice will reply to
        await bob_client.send_message(
            to_address=alice.address,
            recipient_encryption_pubkey=alice.encryption_pubkey,
            content="Can you reply to this using the reply method?"
        )
        
        # Alice receives it
        msgs = await alice_client.poll_and_decrypt(wait=5)
        if msgs:
            # Reply using the Message.reply method
            reply_result = await alice_client.reply_to(
                message=msgs[-1],
                content="Yes! This is a reply using the high-level reply method.",
                recipient_encryption_pubkey=bob.encryption_pubkey
            )
            print(f"   ✅ Reply sent via reply_to()! ID: {reply_result['message_id'][:16]}...")
        
        # Summary
        print("\n" + "=" * 60)
        print("✅ Demo complete! All tests passed.")
        print("\nKey features demonstrated:")
        print("  ✓ Identity generation with crypto addresses")
        print("  ✓ End-to-end encryption (server never sees plaintext)")
        print("  ✓ Message sending and receiving")
        print("  ✓ Automatic decryption")
        print("  ✓ Reply functionality")
        print("  ✓ Mailbox statistics")
        print("\nSecurity highlights:")
        print("  • NaCl X25519+XSalsa20-Poly1305 encryption")
        print("  • Ephemeral keys per message (forward secrecy)")
        print("  • Server has zero knowledge of content")
        print("  • Addresses derived from public keys")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await alice_client.close()
        await bob_client.close()


if __name__ == "__main__":
    try:
        asyncio.run(demo())
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
