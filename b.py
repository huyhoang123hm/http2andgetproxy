import threading
import socks
import ssl
import time
import sys
target_host = "ipv4.icanhazip.com"
target_port = 80
proxy_type_list = {
    "http": socks.HTTP,
    "socks4": socks.SOCKS4,
    "socks5": socks.SOCKS5
}
proxy_type = sys.argv[1]
pysocks_proxy_type = proxy_type_list[proxy_type]
input_file = sys.argv[2]
output_file = sys.argv[3]
timeout = int(sys.argv[4])
total_socks = [proxy.strip() for proxy in open(input_file)]
live_socks = []
live_socks_counter = 0
def connect_socks(socks_address):
    global live_socks_counter
    dead_socks_counter = 0
    headers = "GET / HTTP/1.1\r\nHost: " + target_host + "\r\n\r\n"
    socks_address_split = socks_address.split(":")
    socks_host = socks_address_split[0]
    socks_port = int(socks_address_split[1])
    try:
        socks.setdefaultproxy(pysocks_proxy_type, socks_host, socks_port)
    except:
        total_socks.remove(socks_address)
        return
    while True:
        if dead_socks_counter == 3:
            total_socks.remove(socks_address)
            break
        try:
            conn = socks.socksocket()
            conn.settimeout(timeout)
            conn.connect((target_host, target_port))
            if target_port == 443:
                ssl_context = ssl.SSLContext()
                conn = ssl_context.wrap_socket(conn, server_hostname=target_host)
            conn.send(headers.encode())
            conn.close()
            live_socks.append(socks_address)
            live_socks_counter += 1
            print('Total HTTP working: ' + str(live_socks_counter), end='\r')
            break
        except:
            conn.close()
            dead_socks_counter += 1

thread_list = []
for socks_address in total_socks:
    thread = threading.Thread(target=connect_socks, args=(socks_address, ))
    thread.start()
    thread_list.append(thread)
    sys.stdout.flush()
for thread in thread_list:
    thread.join()
    sys.stdout.flush()
print('Total SOCKS working: ' + str(live_socks_counter))
file = open(output_file, "w")
for socks_address in live_socks:
    file.write(socks_address + "\n")
file.close()
