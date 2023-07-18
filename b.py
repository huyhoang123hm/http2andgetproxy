import threading
import socks
import ssl
import sys

target_host = "ipv4.icanhazip.com"
target_port = 80
proxy_type_list = {"http": socks.HTTP, "socks4": socks.SOCKS4, "socks5": socks.SOCKS5}

def check_socks(socks_address):
    headers = f"GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\n"
    socks_host, socks_port = socks_address.split(":")
    socks_port = int(socks_port)

    try:
        socks.setdefaultproxy(proxy_type_list[proxy_type], socks_host, socks_port)
    except:
        return

    try:
        conn = socks.socksocket()
        conn.settimeout(5)
        conn.connect((target_host, target_port))

        if target_port == 443:
            ssl_context = ssl.SSLContext()
            conn = ssl_context.wrap_socket(conn, server_hostname=target_host)

        conn.send(headers.encode())
        conn.close()

        with lock:
            live_socks.append(socks_address)

    except:
        pass

if __name__ == "__main__":
    proxy_type = sys.argv[1]
    input_file = "proxy.txt"
    output_file = "proxy.txt"

    with open(input_file) as file:
        total_socks = [line.strip() for line in file]

    live_socks = []
    lock = threading.Lock()

    threads = []
    for socks_address in total_socks:
        thread = threading.Thread(target=check_socks, args=(socks_address,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    with open(output_file, "w") as file:
        for socks_address in live_socks:
            file.write(socks_address + "\n")

    print('Total SOCKS working:', len(live_socks))
