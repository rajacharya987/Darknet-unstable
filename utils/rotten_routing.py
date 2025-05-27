import random
from typing import List, Dict, Tuple, Optional
from nacl.public import Box, PublicKey
from nacl.utils import random as nacl_random
import base64
import json
import time

class RottenRouter:
    def __init__(self, crypto_engine):
        self.crypto_engine = crypto_engine
        self.known_peers = {}  # {peer_id: (ip, port, public_key)}
        self.relay_cache = {}  # {message_id: (next_hop, expiry)}
        self.DEFAULT_TTL = 3
        self.MAX_TTL = 5
        self.RELAY_TIMEOUT = 60  # seconds

    def wrap_message(self, message: dict, recipient_key: bytes, route: List[Tuple[str, int, bytes]]) -> dict:
        """
        Wrap a message in multiple encryption layers for Rotten Routing
        
        Args:
            message: The original message dict
            recipient_key: Public key of final recipient
            route: List of relay nodes [(ip, port, public_key), ...]
        
        Returns:
            dict: Wrapped message with routing information
        """
        current_payload = {
            'type': 'message',
            'payload': message,
            'timestamp': int(time.time()),
            'final': True
        }
        
        # Encrypt for final recipient
        box = Box(self.crypto_engine.private_key, PublicKey(recipient_key))
        current_payload = box.encrypt(
            json.dumps(current_payload).encode(),
            nacl_random(Box.NONCE_SIZE)
        )
        current_payload = base64.b64encode(current_payload).decode()

        # Add routing layers
        for relay_ip, relay_port, relay_key in reversed(route):
            next_hop = {
                'type': 'relay',
                'payload': current_payload,
                'next_ip': relay_ip,
                'next_port': relay_port,
                'timestamp': int(time.time()),
                'ttl': self.DEFAULT_TTL
            }
            
            # Encrypt for relay
            box = Box(self.crypto_engine.private_key, PublicKey(relay_key))
            current_payload = box.encrypt(
                json.dumps(next_hop).encode(),
                nacl_random(Box.NONCE_SIZE)
            )
            current_payload = base64.b64encode(current_payload).decode()

        return {
            'type': 'rotten',
            'payload': current_payload,
            'timestamp': int(time.time())
        }

    def unwrap_layer(self, wrapped_message: dict) -> Tuple[dict, Optional[Tuple[str, int]]]:
        """
        Decrypt one layer of a Rotten Routed message
        
        Returns:
            (message_data, next_hop) where next_hop is None if this is the final recipient
        """
        try:
            # Decrypt the current layer
            encrypted = base64.b64decode(wrapped_message['payload'])
            box = Box(self.crypto_engine.private_key, PublicKey(wrapped_message['sender']))
            decrypted = box.decrypt(encrypted)
            message_data = json.loads(decrypted.decode())

            # Check TTL and timestamp
            current_time = int(time.time())
            if current_time - message_data['timestamp'] > self.RELAY_TIMEOUT:
                raise ValueError("Message expired")
            
            if message_data['type'] == 'relay':
                if message_data['ttl'] <= 0:
                    raise ValueError("TTL expired")
                return message_data, (message_data['next_ip'], message_data['next_port'])
            
            elif message_data['type'] == 'message':
                return message_data, None
                
        except Exception as e:
            raise ValueError(f"Failed to unwrap message: {str(e)}")

    def select_route(self, exclude_peers: List[str] = None) -> List[Tuple[str, int, bytes]]:
        """
        Select 2-3 random peers for routing
        
        Args:
            exclude_peers: List of peer IDs to exclude from routing
            
        Returns:
            List of (ip, port, public_key) tuples for routing
        """
        available_peers = [
            (ip, port, key) for pid, (ip, port, key) in self.known_peers.items()
            if not exclude_peers or pid not in exclude_peers
        ]
        
        if len(available_peers) < 2:
            raise ValueError("Not enough peers available for routing")
            
        num_hops = random.randint(2, min(3, len(available_peers)))
        return random.sample(available_peers, num_hops)

    def cleanup_expired_routes(self):
        """Remove expired routes from relay cache"""
        current_time = int(time.time())
        expired = [
            mid for mid, (_, expiry) in self.relay_cache.items()
            if current_time > expiry
        ]
        for mid in expired:
            del self.relay_cache[mid] 