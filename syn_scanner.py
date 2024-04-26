import logging
from scapy.all import TCP, IP, RandShort, sr1

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def syn_scanner(target, ports):
    open_ports = []

    for port in ports:
        src_port = RandShort()
        response = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)

        if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            # 패킷이 TCP 레이어를 포함하는지 확인 -> 해당 패킷이 TCP 프로토콜을 사용하는 패킷임을 확인
            # TCP 헤더의 플래그 확인 -> 패킷의 상태를 나타내고 SYN 플래그의 값이 0x12 이면 TCP 연결 설정 요청 (초기 연결 설정 요청)
            open_ports.append(port)

    return open_ports

if __name__ == "__main__":
    target_ip = "61.42.156.121"
    ports_scan = range(1, 100)
    open_ports = syn_scanner(target_ip, ports_scan)
    print("Open ports:", open_ports)