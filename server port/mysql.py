import socket
import re

def mysql_banner_grabbing(target_ip, port=3306):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        print(f"1: {banner}")
        
        mysql_version_match = re.search(r'version\s+(\S+)', banner)
        if mysql_version_match:
            mysql_version = mysql_version_match.group(1)
            print(f"2: {mysql_version}")
        else:
            print("3")
        
        s.close()
    except Exception as e:
        print(f"4: {e}")

mysql_banner_grabbing('127.0.0.1')