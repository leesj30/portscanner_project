from scapy.all import *
import nmap
import ssl


# 스레드 함수
def scanPort(tgtHost, portNum):
    try:
        port_result = {}
        # SYN 패킷 생성
        response = sr1(IP(dst=tgtHost)/TCP(dport=portNum, flags="S"), timeout=2, verbose=False)
        
        # 만약 응답이 SYN/ACK이면 포트는 열려있음을 의미
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print("[+] Port {} opened".format(portNum))
            port_result[portNum] = "Open"
            
    except Exception as e:
        print("Error:", e)
        
    # 포트가 열려있지 않는 경우 빈 딕셔너리 반환
    return port_result if port_result else None

def ssh_banner_grabbing(target_ip, port=22):
    try:
        # 소켓 객체 생성
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # 소켓 타임아웃 설정 (초 단위)

        # SSH 서비스에 연결 시도
        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        
        # 배너에서 SSH 버전 추출
        ssh_version_match = re.search(r'SSH-(\d+\.\d+)', banner)
        if ssh_version_match:
            ssh_version = ssh_version_match.group(1)
            s.close()
            return {"banner": banner, "version": ssh_version}  # 딕셔너리로 배너 정보와 버전을 반환
        else:
            s.close()
            return {"banner": banner, "version": None}  # 버전을 찾을 수 없는 경우 None 반환
        
    except Exception as e:
        return {"error": f"SSH 서비스에 연결하는 중 오류 발생: {e}"}  # 오류가 발생한 경우 오류 메시지를 딕셔너리로 반환

def ftp_banner_grabbing(target_ip, port=21):
    result = {"banner": None, "version": None, "error": None}
    try:
        # 소켓 객체 생성
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # 소켓 타임아웃 설정 (초 단위)

        # FTP 서비스에 연결 시도
        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        
        # FTP 서비스 배너 정보 저장
        result["banner"] = banner
        
        # 배너에서 FTP 버전 추출
        ftp_version_match = re.search(r'FTP\s+([^\s]+)', banner)
        if ftp_version_match:
            ftp_version = ftp_version_match.group(1)
            result["version"] = ftp_version
        else:
            result["version"] = "Unknown"  # 버전을 찾을 수 없는 경우 Unknown으로 표시
        
        s.close()
    except Exception as e:
        result["error"] = f"FTP 서비스에 연결하는 중 오류 발생: {e}"  # 오류가 발생한 경우 오류 메시지 저장
    
    return result

def get_banner(ip, port):
    banner_info = {}
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, ports=','.join(str(p) for p in port), arguments='-sV')
    
    for host in nm.all_hosts():
        banner_info[host] = {}
        for port in nm[host]['tcp']:
            banner_info[host][port] = {
                "service": nm[host]['tcp'][port]['name'],
                "banner": f"{nm[host]['tcp'][port]['product']} {nm[host]['tcp'][port]['version']}"
            }
    
    return banner_info


def mysql_banner_grabbing(target_ip, port=3306):
    result = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        result["banner"] = banner
        
        mysql_version_match = re.search(r'version\s+(\S+)', banner)
        if mysql_version_match:
            mysql_version = mysql_version_match.group(1)
            result["version"] = mysql_version
        else:
            result["version"] = None
        
        s.close()
    except Exception as e:
        result["error"] = str(e)
    
    return result

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
        
        headers = response.split(b"\r\n\r\n")[0]
        
        # 딕셔너리 구성
        result = {
            "port":80,
            "status": 'opened',
            "service":'HTTP',
            "banner": status_message.decode()
        }
        
        s.close()
        return result
    except Exception as e:
        return {"error": str(e)}

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
        
        headers = response.split(b"\r\n\r\n")[0]
        
        # 딕셔너리 구성
        result = {
            "status_code": status_code,
            "status_message": status_message.decode(),
            "headers": headers.decode()
        }
        
        ssl_socket.close()
        return result
    except Exception as e:
        return {"error": str(e)}

        result["error"] = str(e)
    
    return result
