import os
import sys
import random
import time

if len(sys.argv) < 4:
    print "Usage: python client.py <CLIENT_PORT> <PROXY_PORT> <SERVER_PORT>"
    print "Example: python client.py 20001 20100 20101"
    raise SystemExit

CLIENT_PORT = sys.argv[1]
PROXY_PORT = sys.argv[2]
SERVER_PORT = sys.argv[3]
D = {0: "GET", 1:"POST"}
Cache_Control_list = {0:"Cache-Control:  max-age=60, min-fresh=60, max-stale=120", 1: "Cache-Control: no-store", 2: "Cache-Control: no-cache",
                      3: "Cache-Control: min-fresh=60, max-stale=120", 4: "Cache-Control: min-fresh=60", 5:"Cache-Control: no-cache, min-fresh=60" }
# Cache_Control_list = {0:"Cache-Control:  max-age=60, min-fresh=60, max-stale=120",
#                       1: "Cache-Control: min-fresh=60, max-stale=120", 2: "Cache-Control: min-fresh=60" }
time.sleep(int(random.random()%10) + 1)
num_reqs =0
while True:
    filename = "test%d.data" % (int(random.random()*9)+1)
    num_reqs += 1
    print("val:", num_reqs, num_reqs%5)
    if num_reqs%2 == 0:
        METHOD = D[1]
    else:
        METHOD = D[0]
    Header = Cache_Control_list[int(random.random()*len(Cache_Control_list))]
    Header2 = "'" + Header + "'"
    count = 0
    print("curl --request %s -H %s --proxy 127.0.0.1:%s --local-port %s 127.0.0.1:%s/%s" % (METHOD, Header2, PROXY_PORT, CLIENT_PORT, SERVER_PORT, filename))
    if METHOD == "GET":
        while count < 4:
            count +=1
            os.system("curl --request %s -H %s --proxy 127.0.0.1:%s --local-port %s 127.0.0.1:%s/%s --out %s" % (METHOD, Header2, PROXY_PORT, CLIENT_PORT, SERVER_PORT, filename, filename))
            time.sleep(10)
    else:
        os.system("curl --request %s --proxy 127.0.0.1:%s --local-port %s 127.0.0.1:%s/%s " % (METHOD,  PROXY_PORT, CLIENT_PORT, SERVER_PORT, filename))
        time.sleep(10)
