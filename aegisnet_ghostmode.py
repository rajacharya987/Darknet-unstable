#!/usr/bin/env python3

import socket
import threading
import json
import sys
import os
import time
import base64
import argparse
import upnpy
from typing import Dict, Optional
from utils.crypto import CryptoEngine
from utils.rotten_routing import RottenRouter

class AegisNode:
    def __init__(self, host: str = '0.0.0.0', port: int = 0, username: str = None):
        self.host = host
        self.port = port
        self.username = username or f"anon_{base64.b64encode(os.urandom(3)).decode()[:4]}"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.running = False
        
        # Initialize crypto and routing
        self.crypto = CryptoEngine()
        self.router = RottenRouter(self.crypto)
        
        # Room management
        self.current_room: Optional[str] = None
        self.room_peers: Dict[str, tuple] = {}  # {peer_id: (ip, port, public_key, username)}
        
        # Message handling
        self.message_cache = {}
        self.message_handlers = {
            'join': self.handle_join,
            'leave': self.handle_leave,
            'message': self.handle_message,
            'relay': self.handle_relay
        }
        
        # Setup UPnP for port forwarding
        try:
            self.setup_port_forwarding()
        except Exception as e:
            print(f"⚠️ Port forwarding failed: {e}")

    def setup_port_forwarding(self):
        """Setup UPnP port forwarding"""
        upnp = upnpy.UPnP()
        devices = upnp.discover()
        
        if devices:
            # Get the first IGD (Internet Gateway Device)
            igd = upnp.get_igd()
            # Get actual bound port
            actual_port = self.sock.getsockname()[1]
            
            # Add port mapping
            igd.add_port_mapping(
                external_port=actual_port,
                internal_port=actual_port,
                protocol='UDP',
                ip_address=socket.gethostbyname(socket.gethostname()),
                description='AegisNet P2P Chat'
            )
            print(f"✅ Port {actual_port} forwarded successfully")

    def start(self):
        """Start the peer node"""
        self.running = True
        self.receiver_thread = threading.Thread(target=self._receive_loop)
        self.receiver_thread.daemon = True
        self.receiver_thread.start()
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        actual_port = self.sock.getsockname()[1]
        print(f"🔥 Node started on port {actual_port}")
        print(f"👤 Username: {self.username}")
        print(f"🔑 Public Key: {base64.b64encode(bytes(self.crypto.public_key)).decode()}")

    def stop(self):
        """Stop the peer node"""
        self.running = False
        if self.current_room:
            self.leave_room()
        self.sock.close()

    def _receive_loop(self):
        """Main receive loop for incoming messages"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65536)  # Max UDP packet size
                threading.Thread(target=self._handle_packet, args=(data, addr)).start()
            except Exception as e:
                if self.running:  # Only log if we're still supposed to be running
                    print(f"❌ Error in receive loop: {e}")

    def _cleanup_loop(self):
        """Periodic cleanup of expired messages and routes"""
        while self.running:
            try:
                self.router.cleanup_expired_routes()
                time.sleep(5)  # Cleanup every 5 seconds
            except Exception as e:
                if self.running:
                    print(f"❌ Error in cleanup loop: {e}")

    def _handle_packet(self, data: bytes, addr: tuple):
        """Handle incoming packet"""
        try:
            message = json.loads(data.decode())
            
            if message['type'] == 'rotten':
                # Handle Rotten Routed message
                message_data, next_hop = self.router.unwrap_layer(message)
                
                if next_hop:
                    # Forward to next hop
                    self.forward_message(message_data, next_hop)
                else:
                    # We're the final recipient
                    handler = self.message_handlers.get(message_data['type'])
                    if handler:
                        handler(message_data['payload'], addr)
            else:
                # Direct message
                handler = self.message_handlers.get(message['type'])
                if handler:
                    handler(message['payload'], addr)
                    
        except Exception as e:
            print(f"❌ Error handling packet: {e}")

    def create_room(self) -> str:
        """Create a new room and return the room code"""
        if self.current_room:
            raise ValueError("Already in a room")
            
        # Generate random room code
        room_code = base64.b64encode(os.urandom(8)).decode()
        self.current_room = self.crypto.generate_room_url(room_code)
        self.room_peers = {}
        
        print(f"📢 Created room: {self.current_room}")
        print(f"🔑 Room code: {room_code}")
        return room_code

    def join_room(self, room_code: str, bootstrap_peer: Optional[tuple] = None):
        """Join an existing room"""
        if self.current_room:
            raise ValueError("Already in a room")
            
        # Generate room URL from code
        room_url = self.crypto.generate_room_url(room_code)
        self.current_room = room_url
        
        if bootstrap_peer:
            # Send join request to bootstrap peer
            join_message = {
                'type': 'join',
                'payload': {
                    'room_url': room_url,
                    'username': self.username,
                    'public_key': base64.b64encode(bytes(self.crypto.public_key)).decode()
                }
            }
            self.sock.sendto(json.dumps(join_message).encode(), bootstrap_peer)
            
        print(f"🔗 Joined room: {room_url}")

    def leave_room(self):
        """Leave the current room"""
        if not self.current_room:
            return
            
        # Notify peers
        leave_message = {
            'type': 'leave',
            'payload': {
                'room_url': self.current_room
            }
        }
        
        for peer_addr in self.room_peers.values():
            self.sock.sendto(json.dumps(leave_message).encode(), peer_addr[:2])
            
        self.current_room = None
        self.room_peers = {}
        print("👋 Left room")

    def send_message(self, message: str):
        """Send a message to all peers in the room"""
        if not self.current_room or not self.room_peers:
            raise ValueError("Not in a room or no peers available")
            
        message_data = {
            'content': message,
            'username': self.username,
            'timestamp': time.time()
        }
            
        for peer_id, (ip, port, public_key, username) in self.room_peers.items():
            try:
                # Select route for this peer
                route = self.router.select_route([peer_id])
                
                # Encrypt message for recipient
                encrypted = self.crypto.encrypt_message(json.dumps(message_data), public_key)
                
                # Wrap in Rotten Routing layers
                wrapped = self.router.wrap_message(encrypted, public_key, route)
                
                # Send to first hop
                first_hop = route[0]
                self.sock.sendto(json.dumps(wrapped).encode(), (first_hop[0], first_hop[1]))
                
            except Exception as e:
                print(f"❌ Error sending to peer {username}: {e}")

    def handle_join(self, payload: dict, addr: tuple):
        """Handle incoming join request"""
        if payload['room_url'] == self.current_room:
            # Add peer to room
            peer_id = base64.b64encode(payload['public_key'].encode()).decode()
            self.room_peers[peer_id] = (*addr, base64.b64decode(payload['public_key']), payload['username'])
            
            print(f"👋 {payload['username']} joined the room")
            
            # Send our peer list
            peers_message = {
                'type': 'peers',
                'payload': {
                    'peers': [
                        {
                            'id': pid,
                            'ip': ip,
                            'port': port,
                            'username': uname,
                            'public_key': base64.b64encode(pkey).decode()
                        }
                        for pid, (ip, port, pkey, uname) in self.room_peers.items()
                    ]
                }
            }
            self.sock.sendto(json.dumps(peers_message).encode(), addr)

    def handle_leave(self, payload: dict, addr: tuple):
        """Handle peer leaving"""
        if payload['room_url'] == self.current_room:
            # Remove peer
            peer_to_remove = None
            for pid, (pip, pport, _, _) in self.room_peers.items():
                if (pip, pport) == addr:
                    peer_to_remove = pid
                    break
                    
            if peer_to_remove:
                del self.room_peers[peer_to_remove]
                print(f"👋 Peer left: {addr[0]}:{addr[1]}")

    def handle_message(self, payload: dict, addr: tuple):
        """Handle decrypted message"""
        try:
            message_data = json.loads(self.crypto.decrypt_message(payload))
            print(f"\n💬 {message_data['username']}: {message_data['content']}")
        except Exception as e:
            print(f"❌ Error handling message: {e}")

    def handle_relay(self, payload: dict, addr: tuple):
        """Handle message relay request"""
        try:
            next_hop = (payload['next_ip'], payload['next_port'])
            forwarded = {
                'type': 'rotten',
                'payload': payload['payload'],
                'ttl': payload['ttl'] - 1
            }
            self.sock.sendto(json.dumps(forwarded).encode(), next_hop)
        except Exception as e:
            print(f"❌ Error relaying message: {e}")

    def get_public_ip(self):
        """Get public IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unable to determine"

def main():
    parser = argparse.ArgumentParser(description='AegisNet Ghost Mode')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=0, help='Port to bind to (0 for random)')
    parser.add_argument('--username', help='Your username')
    args = parser.parse_args()

    # Get username if not provided
    username = args.username
    if not username:
        username = input("Enter your username: ").strip()
        while not username:
            print("Username cannot be empty!")
            username = input("Enter your username: ").strip()

    node = AegisNode(args.host, args.port, username)
    
    try:
        node.start()
        
        while True:
            cmd = input("\n🔒 Command (create/join/send/leave/quit): ").strip().lower()
            
            if cmd == 'create':
                node.create_room()
                
            elif cmd == 'join':
                room_code = input("Enter room code: ").strip()
                peer = input("Enter bootstrap peer (ip:port) or press enter for none: ").strip()
                
                bootstrap_peer = None
                if peer:
                    ip, port = peer.split(':')
                    bootstrap_peer = (ip, int(port))
                    
                node.join_room(room_code, bootstrap_peer)
                
            elif cmd == 'send':
                try:
                    message = input("Enter message: ").strip()
                    node.send_message(message)
                except ValueError as e:
                    print(f"❌ Error: {e}")
                    
            elif cmd == 'leave':
                node.leave_room()
                
            elif cmd == 'quit':
                break
                
            else:
                print("❌ Unknown command")
                
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    finally:
        node.stop()

if __name__ == '__main__':
    main() 