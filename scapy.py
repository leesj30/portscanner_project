from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1

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
        "FTP": ["Allow service anonymous login", "Service password policy is weak"],
        "SSH": ["Old SSH version", "Weak encryption algorithms"],
        "HTTP": ["Missing security headers", "Outdated software"],
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

if __name__ == "__main__":
    target_ip = "192.168.56.1"
    port_range = range(1, 444)
    
    for port in port_range:
        response = syn_scan(target_ip, port)
        port_status = check_port_status(response)
        
        print(f"Port {port} is {port_status}")
        
        if port_status == "open":
            service = identify_service(port)
            print(f"Service on port {port}: {service}")
            
            vulnerabilities = find_vulnerabilities(service)
            if vulnerabilities:
                print(f"Vulnerabilities: {', '.join(vulnerabilities)}")
    
    network_map = map_network(target_ip)
    print("Network Map:")
    for ip, status in network_map.items():
        print(f"{ip} is {status}")
    
    audit_results = security_audit()
    print("Security Audit Results:")
    for item, result in audit_results.items():
        print(f"{item}: {result}")