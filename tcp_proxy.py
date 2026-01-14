#!/usr/bin/env python3
"""
Simple TCP proxy to forward localhost:8080 to 192.168.1.200:80
This allows accessing lwIP's HTTP server from Codespace's public URL
"""
import socket
import threading
import sys
import os
import subprocess

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 8080
TARGET_HOST = '192.168.1.200'
TARGET_PORT = 80

def forward(source, destination):
    """Forward data from source socket to destination socket"""
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except Exception:
        pass
    finally:
        # Shutdown write direction to signal EOF
        try:
            destination.shutdown(socket.SHUT_WR)
        except Exception:
            pass

def handle_client(client_sock):
    """Handle a client connection"""
    server_sock = None
    try:
        # Connect to lwIP server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((TARGET_HOST, TARGET_PORT))

        # Start bidirectional forwarding
        c2s = threading.Thread(target=forward, args=(client_sock, server_sock))
        s2c = threading.Thread(target=forward, args=(server_sock, client_sock))
        c2s.start()
        s2c.start()

        # Wait for both directions to complete
        c2s.join()
        s2c.join()
    except Exception as e:
        print(f"Error handling client: {e}")
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
            thread = threading.Thread(target=handle_client, args=(client_sock,))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\nShutting down proxy...")
    finally:
        listen_sock.close()

if __name__ == '__main__':
    main()
