import socket

def mysql_banner_grabbing(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        s.connect((target_ip, port))
        s.send(b"GET / MYSQL/1.1\r\nHost: target_ip\r\n\r\n")

        banner = s.recv(1024).decode('utf-8').strip()
        server_header = s.recv(1024).decode('utf-8').strip()

        print(f"MySQL ���� ��� ����: {banner.splitlines()[0]}")
        print(f"MySQL ���� ���� ����: {server_header}")

        s.close()
    except Exception as e:
        print(f"MySQL ���񽺿� �����ϴ� �� ���� �߻�: {e}")

target_ip = '222.114.120.236'

mysql_port = 22

mysql_banner_grabbing(target_ip, mysql_port)
