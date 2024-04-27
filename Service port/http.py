import socket  

def check_port(target_host, port):
    response = {'port': port, 'status': None, 'error_message': None}  # 응답 데이터 초기화
    
    try:
        with socket.socket() as sock:  # 소켓 객체 생성
            sock.settimeout(5)  
            
            response['status'] = 'open' if not sock.connect_ex((target_host, port)) else 'closed'
            
    except Exception as e:  
        response['status'], response['error_message'] = 'error', str(e)  # 상태를 'error' 설정
    
    return response  # 결과 반환

def fetch_http_header(target_host, port=80):
    response = {'port': port, 'status': None, 'header': None, 'error_message': None}  # 응답 데이터 초기화
    
    try:
        with socket.socket() as sock:  # 소켓 객체 생성
            sock.settimeout(5)  
            
            # 호스트 포트 연결 시도
            if not sock.connect_ex((target_host, port)):  
                response['status'] = 'connected'  # 상태를 'connected' 설정
                
                # HTTP 헤더 요청
                http_request = f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\n\r\n"
                sock.send(http_request.encode())
                
                # 서버로부터 HTTP 헤더를 읽음
                header = b""
                while b"\r\n\r\n" not in header:
                    header += sock.recv(1024)
                
                # HTTP 헤더 디코딩
                response['header'] = header.decode("utf-8").split("\r\n\r\n")[0]
            
            else:
                response['status'] = 'not_connected'  # 상태를 'not_connected' 설정
                
    except Exception as e: 
        response['status'], response['error_message'] = 'error', str(e)  # 상태를 'error' 설정
    
    return response  # 결과 반환

# 타겟 호스트 설정
target_host = input("211.52.42.103")

# 예제
if __name__ == '__main__':  # 메인 실행 블록
    port = 80  # 포트 80 설정
    
    # 포트 상태 확인 함수를 호출 결과
    port_status = check_port(target_host, port)
    print(f"Port {port} status: {port_status['status']}")  # 포트 상태를 출력
    
    # 포트가 열려 있을 경우 HTTP 헤더를 가져오는 함수 호출
    if port_status['status'] == 'open':
        header_info = fetch_http_header(target_host, port)
        print(f"HTTP Header from port {port}:\n{header_info['header']}")  # HTTP 헤더를 출력