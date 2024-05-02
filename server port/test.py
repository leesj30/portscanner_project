import socket
import ssl

def http_banner_grabbing(host, port=80):
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
        s.send(request)
        
        response = s.recv(4096)

        status_line = response.split(b"\r\n")[0]
        status_code = status_line.split()[1]
        status_message = status_line.split(maxsplit=2)[2]
        
        print("HTTP Status:", status_code, status_message.decode())
        
        headers = response.split(b"\r\n\r\n")[0]
        print("Headers:\n" + headers.decode())
        
        s.close()
    except Exception as e:
        print("Error:", e)

def https_banner_grabbing(host, port=443):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        ssl_socket = ssl.wrap_socket(s)
        
        request = b"GET / HTTPS/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
        ssl_socket.send(request)
        
        response = ssl_socket.recv(4096)
        
        status_line = response.split(b"\r\n")[0]
        status_code = status_line.split()[1]
        status_message = status_line.split(maxsplit=2)[2]
        
        print("HTTPS Status:", status_code, status_message.decode())
        
        headers = response.split(b"\r\n\r\n")[0]
        print("Headers:\n" + headers.decode())
        
        ssl_socket.close()
    except Exception as e:
        print("Error occurred:", e)

target_host = "61.42.156.121"

http_banner_grabbing(target_host)
https_banner_grabbing(target_host)
