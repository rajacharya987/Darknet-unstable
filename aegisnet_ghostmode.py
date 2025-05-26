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
from typing import Dict, Optional, List, Tuple
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
            'relay': self.handle_relay,
            'discover': self.handle_discover
        }
        
        # Discovery servers (now using onion addresses)
        self.discovery_servers = [
            ('aegisnet.onion', 40400),     # Tor hidden service
            ('aegisnet-2.onion', 40400),   # Backup hidden service
            ('127.0.0.1', 40400),          # Local development only
        ]
        
        # Initialize Tor connection if available
        self.setup_tor_connection()
        
        # UPnP setup
        self.upnp = None
        self.mapped_port = None
        self.setup_upnp()

    def setup_upnp(self):
        """Setup UPnP with multiple fallback attempts"""
        try:
            import upnpy
            self.upnp = upnpy.UPnP()
            
            # Try to discover UPnP devices
            devices = self.upnp.discover(timeout=2)
            if not devices:
                print("⚠️ No UPnP devices found")
                return
                
            # Try multiple IGDs if available
            for device in devices:
                try:
                    if "InternetGatewayDevice" in device.type:
                        # Get the actual bound port
                        actual_port = self.sock.getsockname()[1]
                        
                        # Try to get WAN IP
                        wan_ip = device.WANIPConn1.GetExternalIPAddress()['NewExternalIPAddress']
                        
                        # Add port mapping
                        device.WANIPConn1.AddPortMapping(
                            NewRemoteHost='',
                            NewExternalPort=actual_port,
                            NewProtocol='UDP',
                            NewInternalPort=actual_port,
                            NewInternalClient=socket.gethostbyname(socket.gethostname()),
                            NewEnabled='1',
                            NewPortMappingDescription='AegisNet P2P Chat',
                            NewLeaseDuration=0
                        )
                        
                        self.mapped_port = actual_port
                        print(f"✅ Port {actual_port} forwarded successfully")
                        print(f"🌍 WAN IP: {wan_ip}")
                        return
                except Exception as e:
                    print(f"⚠️ Failed with IGD {device.friendly_name}: {e}")
                    continue
                    
        except Exception as e:
            print(f"⚠️ UPnP setup failed: {e}")

    def cleanup_upnp(self):
        """Clean up UPnP port mapping"""
        if self.upnp and self.mapped_port:
            try:
                devices = self.upnp.discover(timeout=1)
                for device in devices:
                    if "InternetGatewayDevice" in device.type:
                        device.WANIPConn1.DeletePortMapping(
                            NewRemoteHost='',
                            NewExternalPort=self.mapped_port,
                            NewProtocol='UDP'
                        )
                print(f"✅ Port {self.mapped_port} mapping removed")
            except Exception as e:
                print(f"⚠️ Failed to remove port mapping: {e}")

    def setup_tor_connection(self):
        """Setup Tor connection for anonymous communication"""
        try:
            import stem.process
            import stem.control
            
            # Start Tor process
            self.tor_process = stem.process.launch_tor_with_config(
                config = {
                    'SocksPort': str(9050),
                    'ControlPort': str(9051),
                    'CookieAuthentication': '1'
                },
                init_msg_handler = lambda msg: print(f"Tor: {msg}")
            )
            
            print("✅ Connected to Tor network")
            
        except Exception as e:
            print(f"⚠️ Failed to connect to Tor: {e}")
            print("⚠️ Falling back to direct connection (less anonymous)")
            self.tor_process = None
            
    def discover_room(self, room_code):
        """Discover room through the network without exposing IP"""
        print(f"🔍 Discovering room {room_code}...")
        
        # Create discovery message
        discovery_msg = {
            'type': 'discover',
            'room_code': room_code,
            'public_key': base64.b64encode(bytes(self.crypto.public_key)).decode(),
            'username': self.username
        }
        
        # Try discovery servers through Tor if available
        for server in self.discovery_servers:
            try:
                # Generate anonymous circuit
                circuit = self.router.generate_circuit(destination=server)
                
                # Wrap message in layers
                wrapped = self.router.wrap_message(
                    json.dumps(discovery_msg).encode(),
                    self.crypto.public_key,
                    circuit
                )
                
                # Send through first hop
                first_hop = circuit[0]
                self.sock.sendto(json.dumps(wrapped).encode(), first_hop)
                
                # Wait for response
                try:
                    data, _ = self.sock.recvfrom(65536)
                    response = json.loads(data.decode())
                    
                    if response.get('success'):
                        # Join room through the circuit
                        self.join_room(room_code, circuit=circuit)
                        return
                        
                except socket.timeout:
                    continue
                    
            except Exception as e:
                print(f"Discovery server {server} failed: {e}")
                continue
                
        raise Exception("Room discovery failed: No discovery servers available")
        
    def join_room(self, room_code: str, circuit: List[Tuple[str, int]] = None):
        """Join room through an anonymous circuit"""
        if self.current_room:
            self.leave_room()
            
        # Generate room URL from code
        room_url = self.crypto.generate_room_url(room_code)
        self.current_room = room_url
        
        if not circuit:
            # Create new circuit if none provided
            circuit = self.router.generate_circuit()
            
        # Send join message through circuit
        join_msg = {
            'type': 'join',
            'room_url': room_url,
            'username': self.username,
            'public_key': base64.b64encode(bytes(self.crypto.public_key)).decode()
        }
        
        wrapped = self.router.wrap_message(
            json.dumps(join_msg).encode(),
            self.crypto.public_key,
            circuit
        )
        
        # Send through first hop
        first_hop = circuit[0]
        self.sock.sendto(json.dumps(wrapped).encode(), first_hop)
        
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
        """Send message through anonymous circuit"""
        if not self.current_room or not self.room_peers:
            raise ValueError("Not in a room or no peers available")
            
        message_data = {
            'content': message,
            'username': self.username,
            'timestamp': time.time()
        }
        
        for peer_id, (ip, port, public_key, username) in self.room_peers.items():
            try:
                # Generate new circuit for each peer
                circuit = self.router.generate_circuit(destination=(ip, port))
                
                # Encrypt message for recipient
                encrypted = self.crypto.encrypt_message(json.dumps(message_data), public_key)
                
                # Wrap in routing layers
                wrapped = self.router.wrap_message(encrypted, public_key, circuit)
                
                # Send through first hop
                first_hop = circuit[0]
                self.sock.sendto(json.dumps(wrapped).encode(), first_hop)
                
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
            
            # Broadcast to WebSocket clients if proxy server is available
            try:
                from proxy_server import broadcast_message
                broadcast_message(message_data)
            except ImportError:
                pass  # Running in standalone mode
                
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

    def cleanup(self):
        """Cleanup resources"""
        if self.tor_process:
            self.tor_process.kill()
        self.stop()

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
        node.cleanup()

if __name__ == '__main__':
    main() 