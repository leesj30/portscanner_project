import threading
from scapy.all import IP, TCP, sr1
import socket
import re
import time
import nmap

# 결과 출력 제어
resultLock = threading.Semaphore(value=1)
# 스레드 갯수
maxConnection = 100
# 최대 개수가 maxConnection인 세마포어 생성
connection_lock = threading.BoundedSemaphore(value=maxConnection)
port_result = {}

# SSH 배너 그래빙 함수
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

# FTP 배너 그래빙 함수
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

# MySQL 배너 그래빙 함수
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

# 스레드 함수
def scanPort(tgtHost, portNum):
    try:
        # SYN 패킷 생성
        response = sr1(IP(dst=tgtHost)/TCP(dport=portNum, flags="S"), timeout=2, verbose=False)
        
        # 만약 응답이 SYN/ACK이면 포트는 열려있음을 의미
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            resultLock.acquire()
            print("[+] Port {} opened".format(portNum))
            resultLock.release()
            port_result[portNum] = "Open"
            
            # 포트별로 배너 그래빙 함수 호출
            if portNum == 22:
                ssh_banner_grabbing(tgtHost, portNum)
            elif portNum == 21:
                ftp_banner_grabbing(tgtHost, portNum)
            elif portNum == 3306:
                mysql_banner_grabbing(tgtHost, portNum)
    except Exception as e:
        print("Error:", e)
    finally:
        connection_lock.release()

# nmap을 사용하여 서비스 배너 정보를 가져오는 함수
def get_banner(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, ports=','.join(str(p) for p in ports), arguments='-sV')
    
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for port in nm[host]['tcp']:
            print(f"Port: {port} / Service: {nm[host]['tcp'][port]['name']} / Banner: {nm[host]['tcp'][port]['product']} {nm[host]['tcp'][port]['version']}")

# 메인 함수
def main():
    tgtHost = "211.52.42.173"

    for portNum in range(1024):
        connection_lock.acquire()
        t = threading.Thread(target=scanPort, args=(tgtHost, portNum))
        t.start()
    time.sleep(5)

    print(port_result)
    
    # nmap을 사용하여 서비스 배너 정보 출력
    ip_address = "211.52.42.173"  
    ports = [80, 443]  
    get_banner(ip_address, ports)

if __name__ == "__main__":
    startTime = time.time()
    main()
    endTime = time.time()
    print("executed Time:", (endTime - startTime))