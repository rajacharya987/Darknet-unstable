#!/usr/bin/env python3

import http.server
import socketserver
import urllib.parse
import socket
import threading
import ssl
import re
import os
import json
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse, ParseResult

class AegisProxyHandler(http.server.BaseHTTPRequestHandler):
    # Proxy configuration
    PROXY_PORT = 8889
    CHAT_SERVER_PORT = 7938
    AEGIS_TLD = '.aegisnet'
    
    def extract_room_hash(self, domain):
        """Extract room hash from .aegisnet domain"""
        if self.is_aegis_domain(domain):
            return domain.lower().replace(self.AEGIS_TLD, '')
        return None
        
    def do_CONNECT(self):
        """Handle HTTPS CONNECT requests"""
        host, port = self.path.split(':')
        
        if host.endswith(self.AEGIS_TLD):
            # Redirect .aegisnet domains to local chat server
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            try:
                # Create connection to local chat server
                chat_sock = socket.create_connection(('localhost', self.CHAT_SERVER_PORT))
                client_sock = self.request
                
                # Start bidirectional tunneling
                threading.Thread(target=self.tunnel_traffic, args=(client_sock, chat_sock)).start()
                threading.Thread(target=self.tunnel_traffic, args=(chat_sock, client_sock)).start()
            except Exception as e:
                print(f"Error establishing CONNECT tunnel: {e}")
        else:
            # Regular HTTPS passthrough
            try:
                remote_sock = socket.create_connection((host, int(port)))
                self.send_response(200, 'Connection Established')
                self.end_headers()
                
                # Start bidirectional tunneling
                threading.Thread(target=self.tunnel_traffic, args=(self.request, remote_sock)).start()
                threading.Thread(target=self.tunnel_traffic, args=(remote_sock, self.request)).start()
            except Exception as e:
                self.send_error(502, f'Bad Gateway: {str(e)}')
                
    def tunnel_traffic(self, sock1, sock2):
        """Tunnel traffic between two sockets"""
        try:
            while True:
                data = sock1.recv(4096)
                if not data:
                    break
                sock2.sendall(data)
        except:
            pass
        finally:
            try:
                sock1.close()
                sock2.close()
            except:
                pass

    def do_GET(self):
        """Handle HTTP GET requests"""
        url = urlparse(self.path)
        
        # Check if this is a .aegisnet domain
        if self.is_aegis_domain(url.netloc):
            self.handle_aegis_request(url)
        else:
            self.handle_regular_request()
            
    def do_POST(self):
        """Handle HTTP POST requests"""
        url = urlparse(self.path)
        
        if self.is_aegis_domain(url.netloc):
            self.handle_aegis_request(url)
        else:
            self.handle_regular_request()
            
    def is_aegis_domain(self, domain):
        """Check if domain is a .aegisnet domain"""
        return domain.lower().endswith(self.AEGIS_TLD)
        
    def handle_aegis_request(self, url):
        """Handle requests for .aegisnet domains"""
        try:
            # Extract room hash from domain
            room_hash = self.extract_room_hash(url.netloc)
            if not room_hash:
                self.send_error(400, 'Invalid .aegisnet domain')
                return
            
            # Create connection to local chat server
            conn = HTTPConnection('localhost', self.CHAT_SERVER_PORT)
            
            # Forward the request
            headers = dict(self.headers)
            headers['Host'] = f"{room_hash}.aegisnet"  # Preserve original host
            headers['X-Aegis-Room'] = room_hash  # Add room info
            
            # Construct the path (preserve room in URL)
            target_path = f"/{room_hash}" + (url.path if url.path != '/' else '')
            
            # Read request body if present
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Forward the request to local chat server
            conn.request(
                self.command,
                target_path,
                body,
                headers
            )
            
            # Get response from chat server
            response = conn.getresponse()
            
            # Send response back to client
            self.send_response(response.status)
            
            # Forward response headers
            for header, value in response.getheaders():
                if header.lower() not in ('transfer-encoding',):
                    self.send_header(header, value)
            self.end_headers()
            
            # Forward response body
            self.wfile.write(response.read())
            
        except Exception as e:
            self.send_error(502, f'Bad Gateway: {str(e)}')
            
    def handle_regular_request(self):
        """Handle regular HTTP requests (non-.aegisnet)"""
        try:
            url = urlparse(self.path)
            
            # Create connection to target server
            conn = HTTPConnection(url.netloc)
            
            # Forward the request
            headers = dict(self.headers)
            
            # Read request body if present
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Forward the request
            conn.request(
                self.command,
                url.path + ('?' + url.query if url.query else ''),
                body,
                headers
            )
            
            # Get response
            response = conn.getresponse()
            
            # Send response back to client
            self.send_response(response.status)
            
            # Forward response headers
            for header, value in response.getheaders():
                if header.lower() not in ('transfer-encoding',):
                    self.send_header(header, value)
            self.end_headers()
            
            # Forward response body
            self.wfile.write(response.read())
            
        except Exception as e:
            self.send_error(502, f'Bad Gateway: {str(e)}')
            
    def log_message(self, format, *args):
        """Custom logging format"""
        print(f"🌐 {self.address_string()} - {format%args}")

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread"""
    daemon_threads = True

def generate_proxy_pac():
    """Generate PAC file for automatic proxy configuration"""
    pac_content = """function FindProxyForURL(url, host) {
        // Use PROXY for .aegisnet domains
        if (shExpMatch(host, "*.aegisnet")) {
            return "PROXY localhost:8889";
        }
        
        // Direct connection for everything else
        return "DIRECT";
    }"""
    
    with open('aegis_proxy.pac', 'w') as f:
        f.write(pac_content)
    
    print("📝 Generated proxy.pac file")
    print("➡️  To use: Set browser's automatic proxy configuration URL to:")
    print("   file://" + os.path.abspath('aegis_proxy.pac'))

def main():
    # Generate PAC file
    generate_proxy_pac()
    
    # Start proxy server
    server_address = ('', 8889)
    httpd = ThreadedHTTPServer(server_address, AegisProxyHandler)
    
    print(f"🚀 Starting AegisNet Proxy Server on port {server_address[1]}")
    print("📋 Configure your browser to use this proxy:")
    print(f"   HTTP Proxy: localhost:{server_address[1]}")
    print("   Or use the generated proxy.pac file for automatic configuration")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Shutting down proxy server...")
        httpd.server_close()

if __name__ == '__main__':
    main() 