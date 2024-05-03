from scapy.all import *
import nmap
import ssl


# ������ �Լ�
def scanPort(tgtHost, portNum):
    try:
        port_result = {}
        # SYN ��Ŷ ����
        response = sr1(IP(dst=tgtHost)/TCP(dport=portNum, flags="S"), timeout=2, verbose=False)
        
        # ���� ������ SYN/ACK�̸� ��Ʈ�� ���������� �ǹ�
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print("[+] Port {} opened".format(portNum))
            port_result[portNum] = "Open"
            
    except Exception as e:
        print("Error:", e)
        
    # ��Ʈ�� �������� �ʴ� ��� �� ��ųʸ� ��ȯ
    return port_result if port_result else None

def ssh_banner_grabbing(target_ip, port=22):
    try:
        # ���� ��ü ����
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # ���� Ÿ�Ӿƿ� ���� (�� ����)

        # SSH ���񽺿� ���� �õ�
        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        
        # ��ʿ��� SSH ���� ����
        ssh_version_match = re.search(r'SSH-(\d+\.\d+)', banner)
        if ssh_version_match:
            ssh_version = ssh_version_match.group(1)
            s.close()
            return {"banner": banner, "version": ssh_version}  # ��ųʸ��� ��� ������ ������ ��ȯ
        else:
            s.close()
            return {"banner": banner, "version": None}  # ������ ã�� �� ���� ��� None ��ȯ
        
    except Exception as e:
        return {"error": f"SSH ���񽺿� �����ϴ� �� ���� �߻�: {e}"}  # ������ �߻��� ��� ���� �޽����� ��ųʸ��� ��ȯ

def ftp_banner_grabbing(target_ip, port=21):
    result = {"banner": None, "version": None, "error": None}
    try:
        # ���� ��ü ����
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)  # ���� Ÿ�Ӿƿ� ���� (�� ����)

        # FTP ���񽺿� ���� �õ�
        s.connect((target_ip, port))
        banner = s.recv(1024).decode('utf-8').strip()
        
        # FTP ���� ��� ���� ����
        result["banner"] = banner
        
        # ��ʿ��� FTP ���� ����
        ftp_version_match = re.search(r'FTP\s+([^\s]+)', banner)
        if ftp_version_match:
            ftp_version = ftp_version_match.group(1)
            result["version"] = ftp_version
        else:
            result["version"] = "Unknown"  # ������ ã�� �� ���� ��� Unknown���� ǥ��
        
        s.close()
    except Exception as e:
        result["error"] = f"FTP ���񽺿� �����ϴ� �� ���� �߻�: {e}"  # ������ �߻��� ��� ���� �޽��� ����
    
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
        
        # ��ųʸ� ����
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
        
        # ��ųʸ� ����
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