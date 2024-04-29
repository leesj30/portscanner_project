import socket

def http_banner_grabbing(target_ip, port):
    try:
        # 소켓 객체 생성
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # 소켓 타임아웃 설정 (초 단위)

        # HTTP 서비스에 연결 시도
        s.connect((target_ip, port))
        s.send(b"GET / HTTP/1.1\r\nHost: target_ip\r\n\r\n")
        banner = s.recv(1024).decode('utf-8').strip()
        server_header = s.recv(1024).decode('utf-8').strip()  # 서버 헤더 읽기
        print(f"HTTP 서비스 배너 정보: {banner.splitlines()[0]}")
        print(f"HTTP 서비스 서버 정보: {server_header}")  # 서버 헤더 출력
        
        s.close()
    except Exception as e:
        print(f"HTTP 서비스에 연결하는 중 오류 발생: {e}")

def https_banner_grabbing(target_ip, port):
    try:
        # 소켓 객체 생성
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # 소켓 타임아웃 설정 (초 단위)

        # HTTPS 서비스에 연결 시도
        s.connect((target_ip, port))
        s.send(b"GET / HTTP/1.1\r\nHost: target_ip\r\n\r\n")
        banner = s.recv(1024).decode('utf-8').strip()
        server_header = s.recv(1024).decode('utf-8').strip()  # 서버 헤더 읽기
        print(f"HTTPS 서비스 배너 정보: {banner.splitlines()[0]}")
        print(f"HTTPS 서비스 서버 정보: {server_header}")  # 서버 헤더 출력
        
        s.close()
    except Exception as e:
        print(f"HTTPS 서비스에 연결하는 중 오류 발생: {e}")

# 스캔할 대상의 IP 주소
target_ip = '224.114.110.236'

# 스캔할 포트 번호 (HTTP - 80, HTTPS - 443)
http_port = 80
https_port = 443

# HTTP 서비스 배너 그래빙 실행
http_banner_grabbing(target_ip, http_port)

# HTTPS 서비스 배너 그래빙 실행
https_banner_grabbing(target_ip, https_port)