import socket
import re

def ssh_banner_grabbing(target_ip, port):
    try:
        # 소켓 객체 생성
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # 소켓 타임아웃 설정 (초 단위)

        # SSH 서비스에 연결 시도
        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        print(f"SSH 서비스 배너 정보: {banner}")
        
        # 배너에서 SSH 버전 추출
        ssh_version_match = re.search(r'SSH-(\d+\.\d+)', banner)
        if ssh_version_match:
            ssh_version = ssh_version_match.group(1)
            print(f"SSH 서비스 버전: {ssh_version}")
        else:
            print("SSH 서비스 버전을 찾을 수 없습니다.")
        
        s.close()
    except Exception as e:
        print(f"SSH 서비스에 연결하는 중 오류 발생: {e}")

def ftp_banner_grabbing(target_ip, port):
    try:
        # 소켓 객체 생성
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # 소켓 타임아웃 설정 (초 단위)

        # FTP 서비스에 연결 시도
        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        print(f"FTP 서비스 배너 정보: {banner}")
        
        # 배너에서 FTP 버전 추출
        ftp_version_match = re.search(r'FTP\s+([^\s]+)', banner)
        if ftp_version_match:
            ftp_version = ftp_version_match.group(1)
            print(f"FTP 서비스 버전: {ftp_version}")
        else:
            print("FTP 서비스 버전을 찾을 수 없습니다.")
        
        s.close()
    except Exception as e:
        print(f"FTP 서비스에 연결하는 중 오류 발생: {e}")

# 스캔할 대상의 IP 주소
target_ip = '172.30.1.79'

# 스캔할 포트 번호 (SSH - 22, FTP - 21)
ssh_port = 22
ftp_port = 21

# SSH 서비스 배너 그래빙 실행
ssh_banner_grabbing(target_ip, ssh_port)

# FTP 서비스 배너 그래빙 실행
ftp_banner_grabbing(target_ip, ftp_port)
