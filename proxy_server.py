#!/usr/bin/env python3

import os
import json
import threading
import mimetypes
from flask import Flask, render_template, request, jsonify, send_from_directory, Response, redirect, url_for
from flask_socketio import SocketIO, emit
from werkzeug.serving import make_server
from aegisnet_ghostmode import AegisNode
import socketserver
import socket

# Ensure proper MIME types
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('text/css', '.css')

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(__file__), 'web_ui/templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'web_ui/static')
)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
aegis_node = None
current_room = None
connected_clients = set()

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    connected_clients.add(request.sid)
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    connected_clients.remove(request.sid)
    print(f"Client disconnected: {request.sid}")

@socketio.on('send_message')
def handle_send_message(data):
    if aegis_node and aegis_node.current_room:
        try:
            aegis_node.send_message(data['message'])
            # Message will be broadcasted to all clients when received through the P2P network
        except Exception as e:
            emit('error', {'message': str(e)})

def broadcast_message(message_data):
    """Broadcast message to all connected WebSocket clients"""
    socketio.emit('new_message', message_data, broadcast=True)

@app.after_request
def add_header(response):
    """Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes."""
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files with proper MIME types"""
    print(f"Serving static file: {filename}")
    print(f"Static folder: {app.static_folder}")
    
    if filename.endswith('.js'):
        mimetype = 'application/javascript'
    elif filename.endswith('.css'):
        mimetype = 'text/css'
    else:
        mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    
    try:
        full_path = os.path.join(app.static_folder, filename)
        print(f"Full path: {full_path}")
        print(f"File exists: {os.path.exists(full_path)}")
        
        if not os.path.exists(full_path):
            print(f"File not found: {full_path}")
            return f"File not found: {filename}", 404
            
        response = send_from_directory(app.static_folder, filename)
        response.headers['Content-Type'] = mimetype
        print(f"Serving {filename} with MIME type: {mimetype}")
        return response
    except Exception as e:
        print(f"Static file error: {e}")
        return f"File not found: {filename}", 404

@app.route('/')
def index():
    """Landing page"""
    if aegis_node and aegis_node.current_room:
        return redirect(f"/{aegis_node.current_room}")
    return render_template('index.html')

@app.route('/<room_code>')
def chat_room(room_code):
    """Chat room page - supports both hash and direct room codes"""
    global current_room
    
    # Clean up room code (remove .aegisnet if present)
    room_code = room_code.replace('.aegisnet', '')
    
    # If we're already in this room, just show the chat
    if aegis_node and (aegis_node.current_room == room_code):
        node_port = aegis_node.sock.getsockname()[1]
        public_ip = aegis_node.get_public_ip()
        return render_template('chat.html', 
            room_hash=room_code,
            username=aegis_node.username,
            public_ip=public_ip,
            port=node_port
        )
    
    # If we're in a different room, leave it first
    if aegis_node and aegis_node.current_room:
        try:
            aegis_node.leave_room()
            current_room = None
        except Exception as e:
            print(f"Failed to leave current room: {e}")
            return render_template('index.html', error="Failed to switch rooms. Please try again.")
    
    # Now try to join the new room
    try:
        # Try to join without bootstrap peer first
        try:
            aegis_node.join_room(room_code)
        except Exception as first_try_error:
            print(f"Direct join failed, trying discovery: {first_try_error}")
            # If direct join fails, try discovery
            aegis_node.discover_room(room_code)
            
        current_room = room_code
        
        # Get node connection info
        node_port = aegis_node.sock.getsockname()[1]
        public_ip = aegis_node.get_public_ip()
        
        return render_template('chat.html', 
            room_hash=room_code,
            username=aegis_node.username,
            public_ip=public_ip,
            port=node_port
        )
    except Exception as e:
        print(f"Failed to join room: {e}")
        return render_template('index.html', error="Failed to join room. Please try again.")

@app.route('/api/create_room', methods=['POST'])
def create_room():
    """Create a new chat room"""
    global current_room
    
    try:
        room_code = aegis_node.create_room()
        current_room = room_code
        
        # Get connection info
        node_port = aegis_node.sock.getsockname()[1]
        public_ip = aegis_node.get_public_ip()
        
        return jsonify({
            'success': True,
            'room_code': room_code,
            'room_url': f"{aegis_node.current_room}",
            'public_ip': public_ip,
            'port': node_port
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/join_room', methods=['POST'])
def join_room():
    """Join an existing room"""
    global current_room
    
    data = request.get_json()
    room_code = data.get('room_code')
    
    if not room_code:
        return jsonify({
            'success': False,
            'error': 'Room code is required'
        })
    
    try:
        # If we're in a room, leave it first
        if aegis_node.current_room:
            aegis_node.leave_room()
            
        # Try to join without bootstrap peer first
        try:
            aegis_node.join_room(room_code)
        except Exception as first_try_error:
            print(f"Direct join failed, trying discovery: {first_try_error}")
            # If direct join fails, try discovery
            aegis_node.discover_room(room_code)
            
        current_room = room_code
        
        return jsonify({
            'success': True,
            'room_url': f"{room_code}.aegisnet"
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/leave_room', methods=['POST'])
def leave_room():
    """Leave the current room"""
    global current_room
    
    try:
        aegis_node.leave_room()
        current_room = None
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/send_message', methods=['POST'])
def send_message():
    """Send a message in the current room"""
    if not current_room:
        return jsonify({
            'success': False,
            'error': 'Not in a room'
        })
    
    data = request.get_json()
    message = data.get('message')
    
    if not message:
        return jsonify({
            'success': False,
            'error': 'Message is required'
        })
    
    try:
        aegis_node.send_message(message)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/messages')
def get_messages():
    """Get all messages in the current room"""
    if not current_room:
        return jsonify({
            'success': False,
            'error': 'Not in a room'
        })
    
    try:
        messages = []
        for msg in aegis_node.get_messages():
            messages.append({
                'id': msg.id,
                'username': msg.sender,
                'content': msg.content,
                'timestamp': msg.timestamp
            })
        return jsonify({
            'success': True,
            'messages': messages
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/room_info')
def room_info():
    """Get information about the current room"""
    if not current_room:
        return jsonify({
            'success': False,
            'error': 'Not in a room'
        })
    
    return jsonify({
        'success': True,
        'room_code': current_room,
        'room_url': aegis_node.current_room,
        'peers': len(aegis_node.room_peers)
    })

class AegisProxy:
    def __init__(self, aegis_node):
        self.aegis_node = aegis_node
        self.proxy_port = 8889
        self.web_port = 7938
        self.pac_file = 'aegis_proxy.pac'
        
    def start(self):
        """Start both the proxy server and web interface"""
        global aegis_node
        aegis_node = self.aegis_node
        
        self.generate_pac_file()
        
        # Start proxy server thread
        proxy_thread = threading.Thread(target=self.start_proxy, daemon=True)
        proxy_thread.start()
        
        # Start Flask-SocketIO server thread
        flask_thread = threading.Thread(target=self.start_web_interface, daemon=True)
        flask_thread.start()
        
        print("✅ Starting proxy server...")
        print("📝 Generated proxy.pac file")
        print("➡️  To use: Set browser's automatic proxy configuration URL to:")
        print(f"   file://{os.path.abspath(self.pac_file)}")
        
    def start_web_interface(self):
        """Start the Flask-SocketIO web interface"""
        socketio.run(app, host='127.0.0.1', port=self.web_port)
        
    def start_proxy(self):
        """Start the proxy server thread"""
        server = ProxyServer(('127.0.0.1', self.proxy_port), ProxyHandler)
        server.node_host = '127.0.0.1'
        server.node_port = self.web_port  # Forward to web interface
        print(f"🚀 Starting AegisNet Proxy Server on port {self.proxy_port}")
        print("📋 Configure your browser to use this proxy:")
        print(f"   HTTP Proxy: localhost:{self.proxy_port}")
        print("   Or use the generated proxy.pac file for automatic configuration")
        server.serve_forever()

    def generate_pac_file(self):
        """Generate proxy.pac file for automatic browser configuration"""
        pac_content = f'''function FindProxyForURL(url, host) {{
            if (shExpMatch(host, "*.aegisnet")) {{
                return "PROXY localhost:{self.proxy_port}";
            }}
            return "DIRECT";
        }}'''
        
        with open(self.pac_file, 'w') as f:
            f.write(pac_content)

class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            # Read the HTTP request as binary first
            data = self.request.recv(4096)
            if not data:
                return
                
            # Try to decode the headers portion
            header_end = data.find(b'\r\n\r\n')
            if header_end == -1:
                self.send_error(400, "Invalid HTTP request")
                return
                
            headers = data[:header_end].decode('utf-8', errors='ignore')
            body = data[header_end+4:] if header_end + 4 < len(data) else b''
            
            # Parse the request
            request_lines = headers.split('\n')
            request_line = request_lines[0].strip()
            parts = request_line.split(' ')
            
            if len(parts) != 3:
                self.send_error(400, "Invalid request line")
                return
                
            method, full_path, version = parts
            print(f"Proxy received request: {method} {full_path}")
            
            # Handle CONNECT method for HTTPS
            if method == 'CONNECT':
                try:
                    host, port = full_path.split(':')
                    # Forward HTTPS connection
                    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target.connect((host, int(port)))
                    
                    # Send 200 Connection established
                    self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    
                    # Start bidirectional tunnel
                    self.handle_tunnel(target)
                    return
                except Exception as e:
                    print(f"CONNECT error: {e}")
                    self.send_error(502, "Failed to establish connection")
                    return
            
            # Extract domain and path from full URL if present
            if full_path.startswith('http://'):
                # Remove http:// prefix
                path_parts = full_path[7:].split('/', 1)
                host = path_parts[0]
                path = '/' + path_parts[1] if len(path_parts) > 1 else '/'
            else:
                # Extract host from headers
                host = None
                for line in request_lines[1:]:
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break
                path = full_path
            
            if not host:
                self.send_error(400, "Missing Host header")
                return
            
            # Handle .aegisnet domains
            if host.endswith('.aegisnet'):
                room_hash = host.replace('.aegisnet', '')
                # Ensure path starts with room hash
                if path == '/':
                    modified_path = f"/{room_hash}"
                else:
                    modified_path = f"/{room_hash}{path}" if not path.startswith(f"/{room_hash}") else path
            else:
                modified_path = path
                
            print(f"Request mapped to: {modified_path}")
            
            # Create modified request for Flask
            modified_headers = []
            modified_headers.append(f"{method} {modified_path} HTTP/1.1")
            modified_headers.append(f"Host: localhost:{self.server.node_port}")
            
            # Add remaining headers except host
            for line in request_lines[1:]:
                line = line.strip()
                if line and not line.lower().startswith('host:'):
                    modified_headers.append(line)
            
            # Reconstruct the request
            modified_request = '\r\n'.join(modified_headers).encode('utf-8')
            modified_request += b'\r\n\r\n'
            modified_request += body
            
            print("Modified request headers:")
            print('\n'.join(modified_headers))
            
            # Forward to Flask server
            flask_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            flask_sock.connect(('127.0.0.1', self.server.node_port))
            flask_sock.sendall(modified_request)
            
            # Get response
            response = self.receive_response(flask_sock)
            
            # Send response back to client
            self.request.sendall(response)
            flask_sock.close()
            
        except Exception as e:
            print(f"Proxy error: {e}")
            self.send_error(500, str(e))
        finally:
            self.request.close()
    
    def handle_tunnel(self, target):
        """Handle HTTPS tunnel between client and target"""
        import select
        
        client = self.request
        
        while True:
            # Wait for data from either side
            r, w, e = select.select([client, target], [], [])
            
            if client in r:
                data = client.recv(4096)
                if not data:
                    break
                target.send(data)
                
            if target in r:
                data = target.recv(4096)
                if not data:
                    break
                client.send(data)
                
        target.close()
    
    def receive_response(self, sock):
        """Receive full HTTP response with proper handling of chunked encoding"""
        response = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            
            # Check if we have headers
            if b'\r\n\r\n' in response:
                header_end = response.find(b'\r\n\r\n')
                headers = response[:header_end].decode('utf-8', errors='ignore')
                
                # Check for Content-Length
                content_length = None
                transfer_encoding = None
                for line in headers.split('\r\n'):
                    if line.lower().startswith('content-length:'):
                        content_length = int(line.split(':', 1)[1].strip())
                    elif line.lower().startswith('transfer-encoding:'):
                        transfer_encoding = line.split(':', 1)[1].strip().lower()
                
                # Handle based on response type
                if content_length is not None:
                    # Fixed length response
                    body_received = len(response) - (header_end + 4)
                    if body_received >= content_length:
                        break
                elif transfer_encoding == 'chunked':
                    # Chunked response - check for final chunk
                    if response.endswith(b'0\r\n\r\n'):
                        break
                elif len(chunk) < 4096:
                    # No length indicators and got partial chunk - assume complete
                    break
        
        # Print response status
        status_line = response.split(b'\r\n')[0]
        print("Response status:", status_line.decode('utf-8', errors='ignore'))
        
        return response
            
    def send_error(self, code: int, message: str):
        """Send HTTP error response"""
        response = f"HTTP/1.1 {code} {message}\r\n"
        response += "Content-Type: text/plain\r\n"
        response += f"Content-Length: {len(message)}\r\n"
        response += "\r\n"
        response += message
        self.request.send(response.encode('utf-8'))

class ProxyServer(socketserver.TCPServer):
    allow_reuse_address = True

def start_proxy(host='127.0.0.1', port=7938, node_host='0.0.0.0', node_port=0):
    """Start the proxy server"""
    global aegis_node
    
    # Initialize AegisNode
    aegis_node = AegisNode(node_host, node_port)
    aegis_node.start()
    
    # Start Flask server
    server = make_server(host, port, app)
    server.serve_forever()

if __name__ == '__main__':
    start_proxy() 