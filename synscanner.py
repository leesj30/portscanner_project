import threading
from scapy.all import *
import time

#결과 출력 제어
resultLock = threading.Semaphore(value=1)
#스레드 갯수
maxConnection = 100
#최대 개수가 maxConnection인 세마포어 생성
connection_lock = threading.BoundedSemaphore(value=maxConnection)
port_result = {}

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
            
            # 배너 그래빙 수행
            grab_banner(tgtHost, portNum)
    except Exception as e:
        print("Error:", e)
    finally:
        connection_lock.release()

# 배너 그래빙 함수
def grab_banner(tgtHost, portNum):
    try:
        banner = ""
        # HTTP 서비스인 경우
        if portNum == 80:
            banner = http_banner_grabbing(tgtHost, portNum)
        # 다른 서비스의 경우
        else:
            # 배너 그래빙을 위한 추가적인 처리
            pass
        
        if banner:
            print("[+] Banner for Port {}: {}".format(portNum, banner))
    except Exception as e:
        print("Error:", e)

# HTTP 배너 그래빙 함수
def http_banner_grabbing(tgtHost, portNum):
    try:
        banner = ""
        # HTTP GET 요청을 보내고 서버 응답을 받음
        response = sr1(IP(dst=tgtHost)/TCP(dport=portNum)/Raw(b"GET / HTTP/1.1\r\n\r\n"), timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.haslayer(Raw):
            banner = response[Raw].load.decode()
        return banner
    except Exception as e:
        print("Error:", e)
        return ""

# 메인 함수
def main():
    tgtHost = "ip"

    for portNum in range(1024):
        connection_lock.acquire()
        t = threading.Thread(target=scanPort, args=(tgtHost, portNum))
        t.start()
    time.sleep(5)

    print(port_result)

if __name__ == "__main__":
    startTime = time.time()
    main()
    endTime = time.time()
    print("exceuted Time:", (endTime - startTime))
