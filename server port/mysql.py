import socket

def mysql_banner_grabbing(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        s.connect((target_ip, port))
        s.send(b"GET / MYSQL/1.1\r\nHost: target_ip\r\n\r\n")

        banner = s.recv(1024).decode('utf-8').strip()
        server_header = s.recv(1024).decode('utf-8').strip()

        print(f"MySQL 서비스 배너 정보: {banner.splitlines()[0]}")
        print(f"MySQL 서비스 서버 정보: {server_header}")

        s.close()
    except Exception as e:
        print(f"MySQL 서비스에 연결하는 중 오류 발생: {e}")

target_ip = '222.114.120.236'

mysql_port = 22

mysql_banner_grabbing(target_ip, mysql_port)
