import nmap

def get_banner(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, ports=','.join(str(p) for p in ports), arguments='-sV')
    
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for port in nm[host]['tcp']:
            print(f"Port: {port} / Service: {nm[host]['tcp'][port]['name']} / Banner: {nm[host]['tcp'][port]['product']} {nm[host]['tcp'][port]['version']}")

# IP 주소와 포트 지정
ip_address = "121.184.77.93"  
ports = [80, 443]  

# 서비스 배너 정보 출력
get_banner(ip_address, ports)
