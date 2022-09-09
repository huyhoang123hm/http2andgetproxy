import requests
check='5'
if check=='5':
    a=''
    a=a+requests.get(url='https://api.proxyscrape.com/?request=displayproxies&proxytype=http&country=all').text.strip()+'\n'
    a=a+requests.get(url='https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt').text.strip()+'\n'
    a=a+requests.get(url='https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt').text.strip()+'\n'
    a=a+requests.get(url='https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt').text.strip()+'\n'
    a=a+requests.get(url='https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt').text.strip()+'\n'
    a=a+requests.get(url='https://raw.githubusercontent.com/RX4096/proxy-list/main/online/http.txt').text.strip()+'\n'
    a=a+requests.get(url='https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt').text.strip()+'\n'
    a=a+requests.get(url='https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt').text.strip()+'\n'
    a=a+requests.get(url='https://www.proxy-list.download/api/v1/get?type=http').text.strip()+'\n'
    a=a+requests.get(url='https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all').text.strip()+'\n'
    a=a+requests.get(url='https://openproxylist.xyz/http.txt').text.strip()+'\n'
    a=a+requests.get(url='http://pubproxy.com/api/proxy?limit=10&format=txt&type=http').text.strip()+'\n'
    a=a+requests.get(url='http://www.proxylists.net/http.txt').text.strip()+'\n'

    file=open('proxy.txt','w')
    file.write(a)
    file.close()
    file=open('proxy.txt')
    a=file.readlines()
    file.close()
    file=open('proxy.txt','w')
    for i in a:
      if i.strip()!='':
        file.write(i)
    file.close()


