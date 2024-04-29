import threading
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1
import time

# 결과 출력 제어
resultLock = threading.Semaphore(value=1)
# 스레드 갯수
maxConnection = 100
# 최대 개수가 maxConnection인 세마포어 생성
connection_lock = threading.BoundedSemaphore(value=maxConnection)
port_result = {}

# SYN 핵심기능
def syn_scan(target_ip, port):
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
    response = sr1(syn_packet, timeout=2, verbose=0)
    return response

# 응답 분석 및 확인
def check_port_status(response):
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK
            return "open"
        elif response[TCP].flags == 0x14:  # RST-ACK
            return "closed"
    elif response and response.haslayer(ICMP):
        return "filtered or host is unreachable"
    return "no response"

# 서비스 이름 반환
def identify_service(port):
    common_ports = {
        20: "FTP-DATA",
        21: "FTP-CONTROL",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
    }
    return common_ports.get(port, "Unknown")

# 서비스에 해당하는 취약점 목록 반환
def find_vulnerabilities(service):
    vulnerabilities = {
        "FTP": ["Allow service anonymous login", "Service password policy is weak"], # FTP 서비스에 익명 로그인 허용 + 비밀번호 정책이 약함
        "SSH": ["Old SSH version", "Weak encryption algorithms"], # 오래된 버전 + 암호와 알고리즘이 약함 + 보안에 취약한 서비스 사용 가능성
        "HTTP": ["Missing security headers", "Outdated software"], # 응답 헤더에 보안 관련 헤더가 누락 + 웹서버. SW 버전이 오래되어 보안 업데이트 누락 가능성
    }
    return vulnerabilities.get(service, [])

# 네트워크 매핑
def map_network(target_ip):
    network_map = {}
    ip_prefix = '.'.join(target_ip.split('.')[:-1]) + '.'

    for i in range(1, 255):
        ip = ip_prefix + str(i)
        if ip != target_ip:
            host_status = check_host_status(ip)
            network_map[ip] = host_status
    
    return network_map

# ICMP요청으로 확인 후 반환
def check_host_status(ip):
    response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
    return "alive" if response else "unreachable"

# 시스템 보안 설정 및 검사 후 반환
def security_audit():
    audit_results = {
        "Firewall": "Enabled",
        "Antivirus": "Up-to-date",
        "Encryption": "Enabled",
    }
    return audit_results

# 스레드 함수
def scan_port_thread(tgtHost, portNum):
    try:
        # SYN 패킷 생성
        response = syn_scan(tgtHost, portNum)
        
        # 만약 응답이 SYN/ACK이면 포트는 열려있음을 의미
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            with resultLock:
                print("[+] Port {} opened".format(portNum))
            port_result[portNum] = "Open"
            
    except Exception as e:
        print("Error:", e)
    finally:
        connection_lock.release()

# 메인 함수
def main():
    tgtHost = "127.0.0.1"

    for portNum in range(1024):
        connection_lock.acquire()
        t = threading.Thread(target=scan_port_thread, args=(tgtHost, portNum))
        t.start()
    time.sleep(5)

    print(port_result)

if __name__ == "__main__":
    startTime = time.time()
    main()
    endTime = time.time()
    print("exceuted Time:", (endTime - startTime))
