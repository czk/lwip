#!/usr/bin/env python3
"""
Simple TCP proxy to forward localhost:8080 to 192.168.1.200:80
This allows accessing lwIP's HTTP server from Codespace's public URL

This proxy also handles HTTP/1.0 responses without Content-Length header
by buffering the response and adding Content-Length header for compatibility
with GitHub Codespaces reverse proxy.
"""
import socket
import threading
import sys
import os
import subprocess
import re

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 8080
TARGET_HOST = '192.168.1.200'
TARGET_PORT = 80

# Headers to keep when simplifying requests (lwIP has 1023 byte limit)
KEEP_HEADERS = {
    b'host', b'accept', b'user-agent', b'content-type', b'content-length',
    b'connection', b'cookie'
}

def simplify_request(request_data):
    """
    Simplify HTTP request by removing unnecessary headers.
    GitHub Codespaces adds many extra headers that exceed lwIP's buffer limit.
    """
    try:
        # Split headers and body
        if b'\r\n\r\n' in request_data:
            header_part, body = request_data.split(b'\r\n\r\n', 1)
        else:
            header_part = request_data
            body = b''

        lines = header_part.split(b'\r\n')
        if not lines:
            return request_data

        # Keep first line (GET /path HTTP/1.1)
        new_lines = [lines[0]]

        # Filter headers
        for line in lines[1:]:
            if b':' in line:
                header_name = line.split(b':')[0].strip().lower()
                if header_name in KEEP_HEADERS:
                    new_lines.append(line)

        # Rebuild request
        new_request = b'\r\n'.join(new_lines) + b'\r\n\r\n' + body
        return new_request
    except Exception:
        return request_data

def handle_client(client_sock, addr):
    """Handle a client connection with HTTP response buffering"""
    server_sock = None
    try:
        # Receive HTTP request from client
        request_data = b''
        client_sock.settimeout(5.0)
        while True:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            request_data += chunk
            # Check if we have complete HTTP headers
            if b'\r\n\r\n' in request_data:
                break

        if not request_data:
            print(f"  [{addr[1]}] No request data received")
            return

        # Extract request path for logging
        first_line = request_data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
        print(f"  [{addr[1]}] {first_line}")
        print(f"  [{addr[1]}] Original request size: {len(request_data)} bytes")

        # Simplify request headers to fit lwIP's buffer limit (1023 bytes)
        # Remove unnecessary headers added by Codespaces proxy
        request_data = simplify_request(request_data)
        print(f"  [{addr[1]}] Simplified request size: {len(request_data)} bytes")

        # Connect to lwIP server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(10.0)
        try:
            server_sock.connect((TARGET_HOST, TARGET_PORT))
            print(f"  [{addr[1]}] Connected to lwIP server")
        except Exception as e:
            print(f"  [{addr[1]}] Failed to connect to lwIP: {e}")
            return

        # Send request to lwIP server
        server_sock.sendall(request_data)
        print(f"  [{addr[1]}] Request sent to lwIP")

        # Receive complete response from lwIP server
        response_data = b''
        while True:
            try:
                chunk = server_sock.recv(4096)
                if not chunk:
                    print(f"  [{addr[1]}] lwIP closed connection, received {len(response_data)} bytes total")
                    break
                response_data += chunk
                print(f"  [{addr[1]}] Received {len(chunk)} bytes from lwIP")
            except socket.timeout:
                print(f"  [{addr[1]}] Timeout waiting for lwIP response")
                break

        if not response_data:
            print(f"  [{addr[1]}] No response from lwIP server")
            return

        # Check if response has Content-Length header
        header_end = response_data.find(b'\r\n\r\n')
        if header_end != -1:
            headers = response_data[:header_end]
            body = response_data[header_end + 4:]

            # Check if Content-Length is missing and it's HTTP/1.0
            if b'Content-Length' not in headers and b'HTTP/1.0' in headers:
                # Add Content-Length header
                content_length = len(body)

                # Find position after first line (status line)
                first_line_end = headers.find(b'\r\n')
                if first_line_end != -1:
                    status_line = headers[:first_line_end]
                    rest_headers = headers[first_line_end:]

                    # Upgrade to HTTP/1.1 and add Content-Length and Connection: close
                    new_status_line = status_line.replace(b'HTTP/1.0', b'HTTP/1.1')
                    new_headers = new_status_line + rest_headers + b'\r\nContent-Length: ' + str(content_length).encode() + b'\r\nConnection: close'

                    response_data = new_headers + b'\r\n\r\n' + body
                    print(f"  [{addr[1]}] Response: {content_length} bytes, upgraded to HTTP/1.1")

        # Send modified response to client
        client_sock.sendall(response_data)

    except Exception as e:
        print(f"  [{addr[1]}] Error: {e}")
    finally:
        # Close both sockets
        try:
            client_sock.close()
        except Exception:
            pass
        if server_sock:
            try:
                server_sock.close()
            except Exception:
                pass

def main():
    # Create listening socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((LISTEN_HOST, LISTEN_PORT))
    listen_sock.listen(5)

    print(f"TCP Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Forwarding to {TARGET_HOST}:{TARGET_PORT}")
    print()

    # Print Codespaces public URL if running in Codespaces
    codespace_name = os.environ.get('CODESPACE_NAME')
    if codespace_name:
        # Automatically set port to public
        try:
            subprocess.run(
                ['gh', 'codespace', 'ports', 'visibility', f'{LISTEN_PORT}:public', '-c', codespace_name],
                capture_output=True,
                timeout=5
            )
            print(f"✓ Port {LISTEN_PORT} set to public")
        except Exception as e:
            print(f"Note: Could not auto-set port visibility: {e}")
            print(f"You may need to manually set port {LISTEN_PORT} to 'Public' in the PORTS panel")

        print()
        public_url = f"https://{codespace_name}-{LISTEN_PORT}.app.github.dev"
        print(f"Access URL:")
        print(f"  {public_url}/config.shtml")
    else:
        print(f"Local access: http://localhost:{LISTEN_PORT}")

    print()
    print("Press Ctrl+C to stop")
    print()

    try:
        while True:
            client_sock, addr = listen_sock.accept()
            print(f"Connection from {addr}")
            thread = threading.Thread(target=handle_client, args=(client_sock, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\nShutting down proxy...")
    finally:
        listen_sock.close()

if __name__ == '__main__':
    main()
