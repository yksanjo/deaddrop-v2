#!/usr/bin/env python3
"""
DeadDrop CLI - Command-line interface for agent mailbox
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from deaddrop import AgentIdentity, DeadDropClient


CONFIG_DIR = Path.home() / ".deaddrop"
IDENTITIES_DIR = CONFIG_DIR / "identities"


def ensure_dirs():
    """Ensure config directories exist"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITIES_DIR.mkdir(parents=True, exist_ok=True)


def save_identity(name: str, identity: AgentIdentity):
    """Save identity to file"""
    ensure_dirs()
    identity_file = IDENTITIES_DIR / f"{name}.json"
    with open(identity_file, 'w') as f:
        json.dump(identity.export_keys(), f, indent=2)


def load_identity(name: str) -> AgentIdentity:
    """Load identity from file"""
    identity_file = IDENTITIES_DIR / f"{name}.json"
    if not identity_file.exists():
        print(f"Identity '{name}' not found. Run 'init' first.")
        sys.exit(1)
    
    with open(identity_file) as f:
        data = json.load(f)
    return AgentIdentity.import_keys(data)


def list_identities():
    """List all saved identities"""
    ensure_dirs()
    identities = []
    for f in IDENTITIES_DIR.glob("*.json"):
        identities.append(f.stem)
    return identities


def cmd_init(args):
    """Initialize a new agent identity"""
    ensure_dirs()
    
    if args.name in list_identities() and not args.force:
        print(f"Identity '{args.name}' already exists. Use --force to overwrite.")
        return
    
    identity = AgentIdentity.generate()
    save_identity(args.name, identity)
    
    print(f"✅ Created identity: {args.name}")
    print(f"   Address: {identity.address}")
    print(f"   Signing Key: {identity.signing_pubkey[:40]}...")
    print(f"   Encryption Key: {identity.encryption_pubkey[:40]}...")
    print(f"\n   Share your ADDRESS and ENCRYPTION KEY with others to receive messages.")


def cmd_address(args):
    """Show agent address and keys"""
    identity = load_identity(args.name)
    
    print(f"📋 Identity: {args.name}")
    print(f"   Address: {identity.address}")
    print(f"\n🔑 Signing Public Key:")
    print(f"   {identity.signing_pubkey}")
    print(f"\n🔐 Encryption Public Key (share this):")
    print(f"   {identity.encryption_pubkey}")


def cmd_send(args):
    """Send a message"""
    identity = load_identity(args.from_identity)
    
    client = DeadDropClient(
        server_url=args.server,
        identity=identity
    )
    
    async def do_send():
        try:
            result = await client.send_message(
                to_address=args.to,
                recipient_encryption_pubkey=args.key,
                content=args.message
            )
            print(f"✅ Message sent!")
            print(f"   ID: {result['message_id']}")
            print(f"   Expires: {result['expires_at']}")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            await client.close()
    
    asyncio.run(do_send())


def cmd_poll(args):
    """Poll for messages"""
    identity = load_identity(args.name)
    
    client = DeadDropClient(
        server_url=args.server,
        identity=identity
    )
    
    async def do_poll():
        try:
            if args.watch:
                print(f"🔍 Watching for messages (Ctrl+C to stop)...")
                while True:
                    messages = await client.poll_and_decrypt(wait=30)
                    for msg in messages:
                        print(f"\n📨 From: {msg.sender_address}")
                        try:
                            content = msg.content_str
                            # Try JSON
                            try:
                                data = json.loads(content)
                                print(f"   Content: {json.dumps(data, indent=2)}")
                            except:
                                print(f"   Content: {content}")
                        except:
                            print(f"   [Could not decrypt]")
                        print(f"   Time: {msg.timestamp}")
                        print("-" * 50)
                    
                    if not messages:
                        print(".", end='', flush=True)
            else:
                messages = await client.poll_and_decrypt()
                
                if not messages:
                    print("📭 No messages.")
                    return
                
                print(f"📨 {len(messages)} message(s):\n")
                for msg in messages:
                    print(f"From: {msg.sender_address}")
                    print(f"ID: {msg.id}")
                    try:
                        content = msg.content_str
                        try:
                            data = json.loads(content)
                            print(f"Content: {json.dumps(data, indent=2)}")
                        except:
                            print(f"Content: {content}")
                    except Exception as e:
                        print(f"[Decryption error: {e}]")
                    print(f"Time: {msg.timestamp}")
                    print("-" * 50)
        
        except KeyboardInterrupt:
            print("\n👋 Stopped.")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            await client.close()
    
    asyncio.run(do_poll())


def cmd_stats(args):
    """Show mailbox statistics"""
    identity = load_identity(args.name)
    
    client = DeadDropClient(
        server_url=args.server,
        identity=identity
    )
    
    async def do_stats():
        try:
            stats = await client.get_stats()
            print(f"📊 Mailbox Stats for {identity.address}")
            print(f"   Total messages: {stats['total_messages']}")
            print(f"   Valid messages: {stats['valid_messages']}")
            print(f"   Expired messages: {stats['expired_messages']}")
            print(f"   Capacity used: {stats['capacity_used']:.1%}")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            await client.close()
    
    asyncio.run(do_stats())


def cmd_list(args):
    """List all identities"""
    identities = list_identities()
    
    if not identities:
        print("No identities found. Run 'init' to create one.")
        return
    
    print("📋 Identities:")
    for name in identities:
        try:
            identity = load_identity(name)
            print(f"   {name}: {identity.address}")
        except:
            print(f"   {name}: [error loading]")


def main():
    parser = argparse.ArgumentParser(
        prog='deaddrop',
        description='DeadDrop - Zero-knowledge agent mailbox CLI'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Global options
    parser.add_argument('--server', default='http://localhost:8000',
                       help='DeadDrop server URL')
    
    # init command
    init_parser = subparsers.add_parser('init', help='Create new identity')
    init_parser.add_argument('name', help='Identity name')
    init_parser.add_argument('--force', action='store_true',
                            help='Overwrite existing identity')
    
    # address command
    addr_parser = subparsers.add_parser('address', help='Show address and keys')
    addr_parser.add_argument('name', help='Identity name')
    
    # send command
    send_parser = subparsers.add_parser('send', help='Send a message')
    send_parser.add_argument('from_identity', help='Your identity name')
    send_parser.add_argument('--to', required=True, help='Recipient address')
    send_parser.add_argument('--key', required=True, help='Recipient encryption key')
    send_parser.add_argument('--message', '-m', required=True, help='Message to send')
    
    # poll command
    poll_parser = subparsers.add_parser('poll', help='Poll for messages')
    poll_parser.add_argument('name', help='Identity name')
    poll_parser.add_argument('--watch', '-w', action='store_true',
                            help='Continuously watch for messages')
    
    # stats command
    stats_parser = subparsers.add_parser('stats', help='Show mailbox stats')
    stats_parser.add_argument('name', help='Identity name')
    
    # list command
    subparsers.add_parser('list', help='List identities')
    
    args = parser.parse_args()
    
    if args.command == 'init':
        cmd_init(args)
    elif args.command == 'address':
        cmd_address(args)
    elif args.command == 'send':
        cmd_send(args)
    elif args.command == 'poll':
        cmd_poll(args)
    elif args.command == 'stats':
        cmd_stats(args)
    elif args.command == 'list':
        cmd_list(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
