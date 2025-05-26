#!/usr/bin/env python3

import threading
import sys
import os
import time
import socket
from aegisnet_ghostmode import AegisNode
from proxy_server import AegisProxy
import webbrowser

def print_banner():
    banner = """
    🔐 AegisNet - Darknet Communication Network
    ==========================================
    """
    print(banner)

def get_public_ip():
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
    print_banner()
    
    # Get username
    username = input("Enter your username: ").strip()
    while not username:
        print("Username cannot be empty!")
        username = input("Enter your username: ").strip()
    
    # Create and start node
    node = AegisNode(username=username)
    node.start()
    
    # Get node's actual bound address
    node_ip = node.get_public_ip()
    node_port = node.sock.getsockname()[1]
    
    print("\n🌐 Your connection details:")
    print(f"IP: {node_ip}")
    print(f"Port: {node_port}")
    
    print("\n📋 Choose action:")
    print("1. Generate new room code")
    print("2. Join existing room")
    
    while True:
        choice = input("\nChoice (1/2): ").strip()
        if choice in ['1', '2']:
            break
        print("Invalid choice. Please enter 1 or 2.")

    room_code = None
    if choice == '1':
        room_code = node.create_room()
        print("\n✨ Room created!")
        print("📢 Share these details with others:")
        print(f"Room Code: {room_code}")
        print(f"Host Address: {node_ip}:{node_port}")
    else:
        room_code = input("Enter room code: ").strip()
        peer = input("Enter host address (ip:port): ").strip()
        ip, port = peer.split(':')
        node.join_room(room_code, (ip, int(port)))

    print("\n🚀 Starting web interface...")
    
    # Start proxy and web interface
    proxy = AegisProxy(node)
    proxy.start()
    
    # Wait a moment for servers to start
    time.sleep(2)
    
    # Open web interface in browser using .aegisnet domain
    webbrowser.open(f"http://{node.current_room}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
        node.stop()

if __name__ == '__main__':
    main() 