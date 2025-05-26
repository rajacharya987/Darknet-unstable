import os
import random
from typing import List, Dict, Tuple, Optional
from nacl.public import Box, PublicKey
from nacl.utils import random as nacl_random
import base64
import json
import time
import hashlib

class RottenRouter:
    def __init__(self, crypto_engine):
        self.crypto = crypto_engine
        self.routes: Dict[str, List[Tuple[str, int]]] = {}
        self.route_ttl = 3600  # 1 hour route lifetime
        self.min_hops = 3      # Minimum number of hops for anonymity
        self.max_hops = 5      # Maximum number of hops
        self.known_relays = set()  # Set of known relay nodes
        
    def add_relay(self, address: Tuple[str, int]):
        """Add a known relay node"""
        self.known_relays.add(address)
        
    def generate_circuit(self, destination: Optional[Tuple[str, int]] = None) -> List[Tuple[str, int]]:
        """Generate an anonymous circuit with multiple hops"""
        if not self.known_relays:
            raise ValueError("No relay nodes available")
            
        # Determine number of hops (random between min and max)
        num_hops = random.randint(self.min_hops, self.max_hops)
        
        # Select random relays for the circuit
        available_relays = list(self.known_relays)
        if destination:
            available_relays.append(destination)
            
        if len(available_relays) < num_hops:
            # If not enough relays, duplicate some
            while len(available_relays) < num_hops:
                available_relays.append(random.choice(list(self.known_relays)))
                
        # Shuffle and select hops
        random.shuffle(available_relays)
        circuit = available_relays[:num_hops]
        
        if destination and destination not in circuit:
            # Ensure destination is last hop
            circuit[-1] = destination
            
        return circuit
        
    def wrap_message(self, message: bytes, recipient_key: bytes, route: List[Tuple[str, int]]) -> dict:
        """Wrap message in multiple encryption layers (onion routing)"""
        # Start with the innermost layer (message + recipient key)
        current_layer = {
            'type': 'message',
            'payload': base64.b64encode(message).decode(),
            'recipient_key': base64.b64encode(recipient_key).decode()
        }
        
        # Add layers of encryption for each hop in reverse
        for hop in reversed(route[1:]):  # Skip first hop
            # Generate temporary key for this hop
            hop_key = os.urandom(32)
            
            # Encrypt current layer
            encrypted_data = self.crypto.encrypt_with_key(
                json.dumps(current_layer).encode(),
                hop_key
            )
            
            # Create new layer
            current_layer = {
                'type': 'relay',
                'next_hop': {'ip': hop[0], 'port': hop[1]},
                'hop_key': base64.b64encode(hop_key).decode(),
                'payload': base64.b64encode(encrypted_data).decode()
            }
            
        return {
            'type': 'rotten',
            'route_id': self._generate_route_id(route),
            'ttl': len(route),
            'payload': current_layer
        }
        
    def unwrap_layer(self, message: dict) -> Tuple[dict, Optional[Tuple[str, int]]]:
        """Unwrap one layer of encryption"""
        if message['type'] != 'rotten':
            return message, None
            
        payload = message['payload']
        if payload['type'] == 'relay':
            # Decrypt layer with hop key
            hop_key = base64.b64decode(payload['hop_key'])
            encrypted_data = base64.b64decode(payload['payload'])
            
            try:
                decrypted_data = self.crypto.decrypt_with_key(encrypted_data, hop_key)
                inner_layer = json.loads(decrypted_data.decode())
                next_hop = (payload['next_hop']['ip'], payload['next_hop']['port'])
                return inner_layer, next_hop
            except Exception as e:
                print(f"Failed to decrypt layer: {e}")
                return None, None
        else:
            # Final layer with actual message
            return payload, None
            
    def _generate_route_id(self, route: List[Tuple[str, int]]) -> str:
        """Generate unique ID for a route"""
        route_str = ','.join(f"{ip}:{port}" for ip, port in route)
        return hashlib.sha256(route_str.encode()).hexdigest()[:16]
        
    def cleanup_expired_routes(self):
        """Remove expired routes"""
        current_time = time.time()
        expired = []
        
        for route_id, (timestamp, _) in self.routes.items():
            if current_time - timestamp > self.route_ttl:
                expired.append(route_id)
                
        for route_id in expired:
            del self.routes[route_id] 