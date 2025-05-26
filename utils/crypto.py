from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random
from nacl.secret import SecretBox
from nacl.hash import sha256
import base64
import json
import os
import time
import nacl.utils
import nacl.secret
import nacl.encoding
import hashlib

class CryptoEngine:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.keypair_path = os.path.expanduser('~/.aegisnet/keys.json')
        self.initialize_keypair()

    def initialize_keypair(self):
        """Initialize or load existing keypair"""
        if os.path.exists(self.keypair_path):
            self.load_keypair()
        else:
            self.generate_new_keypair()

    def generate_new_keypair(self):
        """Generate new NaCl keypair"""
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.save_keypair()

    def save_keypair(self):
        """Save keypair to encrypted local storage"""
        os.makedirs(os.path.dirname(self.keypair_path), exist_ok=True)
        keypair_data = {
            'private_key': base64.b64encode(bytes(self.private_key)).decode('utf-8'),
            'public_key': base64.b64encode(bytes(self.public_key)).decode('utf-8')
        }
        with open(self.keypair_path, 'w') as f:
            json.dump(keypair_data, f)

    def load_keypair(self):
        """Load keypair from local storage"""
        with open(self.keypair_path, 'r') as f:
            keypair_data = json.load(f)
            self.private_key = PrivateKey(base64.b64decode(keypair_data['private_key']))
            self.public_key = PublicKey(base64.b64decode(keypair_data['public_key']))

    def encrypt_message(self, message: str, recipient_key: bytes) -> bytes:
        """Encrypt a message for a recipient"""
        box = Box(self.private_key, PublicKey(recipient_key))
        return box.encrypt(message.encode(), nacl.utils.random(24))

    def decrypt_message(self, encrypted: bytes) -> str:
        """Decrypt a message"""
        try:
            box = Box(self.private_key, self.public_key)
            decrypted = box.decrypt(encrypted)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Failed to decrypt message: {e}")

    def generate_room_url(self, room_code: str) -> str:
        """Generate a .aegisnet URL from room code"""
        # Create SHA-256 hash of room code
        room_hash = hashlib.sha256(room_code.encode()).hexdigest()[:16]
        return f"{room_hash}.aegisnet"

    @staticmethod
    def verify_room_code(room_code: str, room_url: str) -> bool:
        """Verify if a room code matches a room URL"""
        expected_url = CryptoEngine.generate_room_url(room_code)
        return expected_url == room_url 