import concurrent.futures
import time
from portscan import *

def scan_all(host):
    results = []
    resultLock = threading.Semaphore(value=1)
    maxConnection = 100
    connection_lock = threading.BoundedSemaphore(value=maxConnection)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scanPort, host, portNum): portNum for portNum in range(1024)}
        for future in concurrent.futures.as_completed(futures):
            portNum = futures[future]
            try:
                result = future.result()
                if result is not None:  # 포트가 열려 있을 때만 결과를 수집
                    with resultLock:
                        results.append(result)
            except Exception as e:
                print(f"Error scanning port {portNum}: {e}")
    
    return results

def scan_serviceport(host):
    
    result = [
        (ssh_banner_grabbing(host)),
        (ftp_banner_grabbing(host)),
        (http_banner_grabbing(host)),
        (https_banner_grabbing(host)),
        #(get_banner(host, [80, 443])),
        (mysql_banner_grabbing(host))
    ]
    
    return result

if __name__ == "__main__":
    host = '61.42.156.121'
    startTime = time.time()
    scan_all(host)
    scan_serviceport(host)
    endTime = time.time()
    print("Executed Time:", (endTime - startTime))
