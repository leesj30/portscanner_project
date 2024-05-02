import threading
from scapy.all import IP, TCP, sr1
import socket
import re
import time
import nmap


resultLock = threading.Semaphore(value=1)
maxConnection = 100
connection_lock = threading.BoundedSemaphore(value=maxConnection)
open_ports = []

def ssh_banner_grabbing(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        print(f"1: {banner}")
        
        ssh_version_match = re.search(r'SSH-(\d+\.\d+)', banner)
        if ssh_version_match:
            ssh_version = ssh_version_match.group(1)
            print(f"2: {ssh_version}")
        else:
            print("3")
        
        s.close()
    except Exception as e:
        print(f"4: {e}")

def ftp_banner_grabbing(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        print(f"1: {banner}")

        ftp_version_match = re.search(r'FTP\s+([^\s]+)', banner)
        if ftp_version_match:
            ftp_version = ftp_version_match.group(1)
            print(f"2: {ftp_version}")
        else:
            print("3")
        
        s.close()
    except Exception as e:
        print(f"4: {e}")


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


def http_banner_grabbing(target_ip, port):
    response_data = {'port':port, 'status':'closed', 'service':'HTTP'}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        s.connect((target_ip, port))
        s.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        banner = s.recv(1024).decode('utf-8').strip()
        response_data['status'] = 'open'
        response_data['banner'] = banner
        
        s.close()
    except Exception as e:
        print(f"Error: {e}")

    return response_data


def scanPort(tgtHost, portNum):
    try:
        response = sr1(IP(dst=tgtHost)/TCP(dport=portNum, flags="S"), timeout=2, verbose=False)
        
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            resultLock.acquire()
            resultLock.release()
            open_ports.append(portNum)
            
            if portNum == 22:
                ssh_banner_grabbing(tgtHost, portNum)
            elif portNum == 21:
                ftp_banner_grabbing(tgtHost, portNum)
            elif portNum == 80:
                http_banner_grabbing(tgtHost, portNum)
            elif portNum == 3306:
                mysql_banner_grabbing(tgtHost, portNum)
    except Exception as e:
        print("Error:", e)
    finally:
        connection_lock.release()

def main():
    tgtHost = "192.168.75.129"
    for portNum in range(1024):
        connection_lock.acquire()
        t = threading.Thread(target=scanPort, args=(tgtHost, portNum))
        t.start()
    time.sleep(5)
    print(open_ports)
    return open_ports


    

if __name__ == "__main__":
    startTime = time.time()
    main()
    endTime = time.time()
    print("executed Time:", (endTime - startTime))