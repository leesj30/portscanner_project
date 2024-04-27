import socket

def check_port(target_host, port):
    response = {'port': port, 'status': None, 'error_message': None}
    
    try:
        with socket.create_connection((target_host, port), timeout=5) as sock:
            response['status'] = 'open'
    except Exception as e:
        response['status'] = 'closed' if 'timed out' in str(e) else 'error'
        response['error_message'] = str(e)
    
    return response

def fetch_https_header(target_host, port=443):
    response = {'port': port, 'status': None, 'header': None, 'error_message': None}
    
    try:
        with socket.create_connection((target_host, port), timeout=5) as sock:
            sock.send(f"GET / HTTPS/1.1\r\nHost: {target_host}\r\n\r\n".encode())
            header = b""
            while b"\r\n\r\n" not in header:
                header += sock.recv(1024)
            response['status'] = 'connected'
            response['header'] = header.decode("utf-8").split("\r\n\r\n")[0]
    except Exception as e:
        response['status'] = 'not_connected' if 'timed out' in str(e) else 'error'
        response['error_message'] = str(e)
    
    return response

target_host = input("211.52.42.103")
port = 443

port_status = check_port(target_host, port)
print(f"Port {port} status: {port_status['status']}")

if port_status['status'] == 'open':
    header_info = fetch_https_header(target_host, port)
    print(f"HTTPS Header:\n{header_info['header']}")