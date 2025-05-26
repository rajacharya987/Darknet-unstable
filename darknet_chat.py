#!/usr/bin/env python3

import socket
import threading
import json
import sys
import os
import time
import base64
import nacl.utils
import nacl.secret
import nacl.public
from nacl.encoding import Base64Encoder

class DarknetChat:
    def __init__(self):
        # Generate keypair
        self.private_key = nacl.public.PrivateKey.generate()
        self.public_key = self.private_key.public_key
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 0))  # Bind to random port
        
        # Get actual bound port
        self.port = self.sock.getsockname()[1]
        
        # Room state
        self.room_code = None
        self.peers = {}  # {username: (ip, port, public_key)}
        self.username = None
        self.running = False

    def start(self):
        """Start the chat client"""
        # Get username
        while not self.username:
            self.username = input("Enter your username: ").strip()
            if not self.username:
                print("Username cannot be empty!")

        print(f"\n🔥 Chat started on port {self.port}")
        print(f"👤 Username: {self.username}")
        print(f"🔑 Your public key: {base64.b64encode(bytes(self.public_key)).decode()}")
        
        # Start receiver thread
        self.running = True
        threading.Thread(target=self._receive_loop, daemon=True).start()
        
        # Main command loop
        while True:
            print("\n📋 Commands:")
            print("1. Create room")
            print("2. Join room")
            print("3. Quit")
            
            cmd = input("\nChoice: ").strip()
            
            if cmd == '1':
                self._create_room()
            elif cmd == '2':
                self._join_room()
            elif cmd == '3':
                break
            else:
                print("Invalid choice!")

    def _create_room(self):
        """Create a new chat room"""
        # Generate random room code
        self.room_code = base64.b64encode(os.urandom(8)).decode()
        print(f"\n✨ Created room!")
        print(f"📢 Room code: {self.room_code}")
        print(f"🔌 Your address: {socket.gethostbyname(socket.gethostname())}:{self.port}")
        
        # Start chat mode
        self._chat_mode()

    def _join_room(self):
        """Join an existing room"""
        room_code = input("Enter room code: ").strip()
        host = input("Enter host IP: ").strip()
        port = int(input("Enter host port: ").strip())
        
        # Send join request
        join_msg = {
            'type': 'join',
            'username': self.username,
            'public_key': base64.b64encode(bytes(self.public_key)).decode()
        }
        self.sock.sendto(json.dumps(join_msg).encode(), (host, port))
        
        # Wait for response
        print("\n⏳ Waiting for response...")
        time.sleep(2)  # Give time for response
        
        if self.room_code:
            print("✅ Joined room!")
            self._chat_mode()
        else:
            print("❌ Failed to join room")

    def _chat_mode(self):
        """Enter chat mode"""
        print("\n💬 Chat mode - type /quit to exit")
        
        while True:
            msg = input().strip()
            
            if msg == '/quit':
                self._leave_room()
                break
            
            if msg and self.peers:
                # Encrypt and send to all peers
                for username, (ip, port, public_key) in self.peers.items():
                    try:
                        # Create box for encryption
                        box = nacl.public.Box(self.private_key, 
                            nacl.public.PublicKey(base64.b64decode(public_key)))
                            
                        # Encrypt message
                        encrypted = box.encrypt(
                            f"{self.username}: {msg}".encode(),
                            nacl.utils.random(24)
                        )
                        
                        # Send encrypted message
                        self.sock.sendto(
                            json.dumps({
                                'type': 'message',
                                'data': base64.b64encode(encrypted).decode()
                            }).encode(),
                            (ip, port)
                        )
                    except Exception as e:
                        print(f"❌ Error sending to {username}: {e}")

    def _receive_loop(self):
        """Handle incoming messages"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65536)
                msg = json.loads(data.decode())
                
                if msg['type'] == 'join':
                    # Handle join request
                    if not self.room_code:
                        continue
                        
                    username = msg['username']
                    public_key = msg['public_key']
                    
                    # Add peer
                    self.peers[username] = (addr[0], addr[1], public_key)
                    print(f"\n👋 {username} joined the room")
                    
                    # Send room info back
                    self.sock.sendto(
                        json.dumps({
                            'type': 'room_info',
                            'room_code': self.room_code,
                            'username': self.username,
                            'public_key': base64.b64encode(bytes(self.public_key)).decode()
                        }).encode(),
                        addr
                    )
                    
                elif msg['type'] == 'room_info':
                    # Handle room join response
                    self.room_code = msg['room_code']
                    username = msg['username']
                    public_key = msg['public_key']
                    self.peers[username] = (addr[0], addr[1], public_key)
                    
                elif msg['type'] == 'message':
                    # Decrypt and display message
                    try:
                        encrypted = base64.b64decode(msg['data'])
                        
                        # Try to decrypt with our private key
                        for username, (_, _, public_key) in self.peers.items():
                            try:
                                box = nacl.public.Box(
                                    self.private_key,
                                    nacl.public.PublicKey(base64.b64decode(public_key))
                                )
                                decrypted = box.decrypt(encrypted)
                                print(f"\n{decrypted.decode()}")
                                break
                            except:
                                continue
                                
                    except Exception as e:
                        print(f"❌ Error decrypting message: {e}")
                        
            except Exception as e:
                if self.running:
                    print(f"❌ Error receiving message: {e}")

    def _leave_room(self):
        """Leave the current room"""
        if self.room_code:
            # Notify peers
            for username, (ip, port, _) in self.peers.items():
                try:
                    self.sock.sendto(
                        json.dumps({
                            'type': 'leave',
                            'username': self.username
                        }).encode(),
                        (ip, port)
                    )
                except:
                    pass
                    
            self.room_code = None
            self.peers = {}
            print("\n👋 Left room")

    def stop(self):
        """Stop the chat client"""
        self.running = False
        self._leave_room()
        self.sock.close()

def main():
    chat = DarknetChat()
    try:
        chat.start()
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    finally:
        chat.stop()

if __name__ == '__main__':
    main() 