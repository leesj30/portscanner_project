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
