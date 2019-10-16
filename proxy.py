""" HTTP Proxy that does caching based on cache control header and if req is repeated 3 times in 5 min.
It also blocks access to domains listed in blacklist.txt, It allows access to
these bloked_domains only after base64 authentication of user name and password based on info in
auth_fle.txt """

import base64
import socket
import sys
import os
import datetime
import time
import json
import threading
import _thread
import ipaddress

MAX_CONNECTIONS = 100
BUFFER_SIZE = 4096
CACHE_DIR = "./cache"
BLACKLIST_FILE = "blacklist.txt"
AUTH_FILE = "auth_file.txt"
MAX_CACHE_BUFFER = 3
NO_OF_URL_REPEATS_TO_TRIGGER_CACHING = 3
TIME_INTERVAL_FOR_REPEATS = 5
PROXY_PORT = 20100
MIN_CLIENT_PORT = 20000
MAX_CLIENT_PORT = 20099
MIN_SERVER_PORT = 20101
MAX_SERVER_PORT = 20200
blocked_domains = []
previleged_users = []
CRLF2 = b"\r\n\r\n"

def get_previleged_users():
    '''  reads user passwords from auth file to allow access to block listed domains '''
    file = open(AUTH_FILE, "r")
    data = ""
    while True:
        chunk = file.read()
        if not chunk:
            break
        data += chunk
    file.close()
    data = data.splitlines()
    for value in data:
        previleged_users.append(base64.b64encode(str.encode(value)))

def get_blocked_domains():
    '''  reads blocked domains from blacklist file '''
    file = open(BLACKLIST_FILE, "r")
    data = ""
    while True:
        chunk = file.read()
        if not chunk:
            break
        data += chunk
    file.close()
    data_list = data.splitlines()
    for cidr in data_list:
        if "/" in cidr:
            pos = cidr.find(":")
            cidr_ip = cidr[:pos]
            network = ipaddress.IPv4Network(cidr_ip)
            # print(network[0], network[-1])
            for ip in network:
                addr = str(ip) +cidr[pos:]
                blocked_domains.append(addr)
        else:
            blocked_domains.append(cidr)
    print(blocked_domains)

def proxy_init():
    ''' setup cache and read block listed domains and previleged users '''
    if not os.path.isdir(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    for file in os.listdir(CACHE_DIR):
        os.remove(CACHE_DIR + "/" + file)
    get_blocked_domains()
    get_previleged_users()

def get_lock(fileurl):
    '''  lock fileurl '''
    if fileurl in locks:
        lock = locks[fileurl]
    else:
        lock = threading.Lock()
        locks[fileurl] = lock
    lock.acquire()

def release_lock(fileurl):
    '''  unlock fileurl '''
    if fileurl in locks:
        lock = locks[fileurl]
        lock.release()
    else:
        print("Lock problem")
        sys.exit()

def update_cache_options_in_msg_log(fileurl, client_addr, cache_control_info):
    ''' add url entry to msg log to see if it repeated 3 times in 5 mins '''
    fileurl = fileurl.replace("/", "__")
    if not fileurl in msg_logs:
        print("file url not found")
        return
    size = len(msg_logs[fileurl])-1
    msg_logs[fileurl][size].update({
        "server_cache_control":cache_control_info["server_cache_control"],
        "server_max_age":cache_control_info["server_max_age"],
        "server_revalidate":cache_control_info["server_revalidate"]
        })
    # print("update_cache_options_in_msg_log", msg_logs[fileurl])

def add_url_to_msg_log(fileurl, client_addr, cache_control_info):
    ''' add url entry to msg log to see if it repeated 3 times in 5 mins '''

    # print("add_url_to_msg_log:", client_addr, json.dumps(client_addr))
    fileurl = fileurl.replace("/", "__")
    if not fileurl in msg_logs:
        msg_logs[fileurl] = []
    dt = time.strptime(time.ctime(), "%a %b %d %H:%M:%S %Y")

    msg_logs[fileurl].append({
        "datetime" : dt,
        "client" : client_addr,
        "client_cache_control": cache_control_info["client_cache_control"],
        "client_max_age":cache_control_info["client_max_age"],
        "client_min_fresh":cache_control_info["client_min_fresh"],
        "client_max_stale":cache_control_info["client_max_stale"],
        })
    # print("addlog", msg_logs[fileurl])

def is_validation_needed(fileurl, last_mtime):
    ''' check if we need to validate cache info before sending the reponse from cache '''
    # print("is_validation_needed")
    # server_max_age = 0
    server_max_age = -1
    server_validate = False
    server_cache_control = 'None'
    stale = False
    try:
        msg_log_arr = msg_logs[fileurl.replace("/", "__")]
        if len(msg_log_arr) < NO_OF_URL_REPEATS_TO_TRIGGER_CACHING:
            print("is_validation_needed:not enough entries to catch return false")
            return False, stale

        msg = msg_log_arr[:(len(msg_log_arr)-2)]
        max_age = int(msg[0]['client_max_age'])
        min_fresh = int(msg[0]['client_min_fresh'])
        max_stale = int(msg[0]["client_max_stale"])

        if "no-cache" in msg[0]["client_cache_control"]:
            print("is_validation_needed: no-cahe returning true")
            return True, stale
        try:
            # print(msg[0])
            server_max_age = int(msg[0]["server_max_age"])
            # server_max_age = msg[0]["server_max_age"]
            server_validate = msg[0]["server_revalidate"]
            server_cache_control = msg[0]["server_cache_control"]
            print(server_max_age, server_validate, server_cache_control)
        except KeyError:
            pass
            # print("servercache control key error")
        finally:
            print(max_age, min_fresh, max_stale, server_max_age)
            if "no-cache" in server_cache_control:
                print("is_validation_needed: no-cahe server returning true")
                return True, stale
            if max_age >= 0 and server_max_age < max_age:
                if server_max_age >=0:
                    max_age = server_max_age
            elif max_age == -1:
                max_age = server_max_age

            if max_age == -1 and min_fresh == -1 and server_validate is True:
                print("is_validation_needed:no time and server validate True")
                return True, stale
            delta = max_age
            if delta >= 0:
                if delta > min_fresh:
                    if min_fresh >= 0:
                        delta = min_fresh
            else:
                delta = min_fresh

            if last_mtime is None:
                print("is_validation_needed:last_mtime none False")
                return False, stale
            # print(delta, last_mtime)
            delta_time = datetime.timedelta(seconds=delta)
            last_mtime2 = datetime.datetime.fromtimestamp(time.mktime(last_mtime))
            # print(delta_time, last_mtime2, datetime.datetime.now())
            if  datetime.datetime.now() - last_mtime2 <= delta_time:
                print("is_validation_needed:max_age or min fresh in control return false")
                return False, stale
            if server_validate is True:
                print("is_validation_needed:server validate after becoming stale return true")
                return True, stale
            if max_stale > 0:
                max_stale_time = datetime.timedelta(seconds=max_stale)
                if  datetime.datetime.now() - last_mtime2 <= max_stale_time:
                    print("is_validation_needed:no server validate after becoming stale return stale and  false")
                    return False, True
            print("is_validation_needed:No case match return true")
            return True, stale
    except Exception as exception:
        print("Exception is_validation_needed:", exception)
        return False, False
def is_caching_needed(fileurl):
    ''' check is we need to cache this url repsonse '''
    try:
        msg_log_arr = msg_logs[fileurl.replace("/", "__")]
        if len(msg_log_arr) < NO_OF_URL_REPEATS_TO_TRIGGER_CACHING:
            print("is_caching_needed num logs are less than trigger threshold returning false")
            return False
        max_repeat_url_idx = len(msg_log_arr)-NO_OF_URL_REPEATS_TO_TRIGGER_CACHING
        last_max_repeat_timestamp = msg_log_arr[max_repeat_url_idx]["datetime"]
        last_repeat_time = datetime.datetime.fromtimestamp(time.mktime(last_max_repeat_timestamp))
        delta_time = datetime.timedelta(minutes=TIME_INTERVAL_FOR_REPEATS)
        if  last_repeat_time + delta_time >= datetime.datetime.now():
            return True
        return False
    except Exception as exception:
        print("Exeception is_cahing_needed", exception)
        return False

def get_current_cache_info(fileurl):
    ''' check if file already present in cache '''

    if fileurl.startswith("/"):
        fileurl = fileurl.replace("/", "", 1)

    cache_path = CACHE_DIR + "/" + fileurl.replace("/", "__")

    if os.path.isfile(cache_path):
        last_mtime = time.strptime(time.ctime(os.path.getmtime(cache_path)), "%a %b %d %H:%M:%S %Y")
        return cache_path, last_mtime

    return cache_path, None

def get_cache_connnection_info(client_addr, connnection_info, cache_control_info):
    ''' Collect cache info and add to connection to handle msg accordingly '''

    if "no-store".lower() in cache_control_info["client_cache_control"].lower():
        # print("nostore match setting caching to false")
        connnection_info["caching_needed"] = False
        connnection_info["cache_path"] = None
        connnection_info["last_mtime"] = None
        return connnection_info

    get_lock(connnection_info["url"])
    add_url_to_msg_log(connnection_info["url"], client_addr, cache_control_info)
    caching_needed = is_caching_needed(connnection_info["url"])
    cache_path, last_mtime = get_current_cache_info(connnection_info["url"])
    release_lock(connnection_info["url"])
    connnection_info["caching_needed"] = caching_needed
    connnection_info["cache_path"] = cache_path
    connnection_info["last_mtime"] = last_mtime
    return connnection_info

def get_space_for_cache():
    ''' If cache is full then make space for new response by deleting least recently used item '''
    cache_files = os.listdir(CACHE_DIR)
    if len(cache_files) < MAX_CACHE_BUFFER:
        return
    for file in cache_files:
        get_lock(file)

    last_mtime = min(msg_logs[file][-1]["datetime"] for file in cache_files)
    file_to_del = [file for file in cache_files if msg_logs[file][-1]["datetime"] == last_mtime][0]

    os.remove(CACHE_DIR + "/" + file_to_del)
    for file in cache_files:
        release_lock(file)

def parse_cache_control_request(cache_ctrl):
    ''' Folowing can be used by client in request
    Cache-Control: max-age=<seconds>
    Cache-Control: max-stale[=<seconds>]
    Cache-Control: min-fresh=<seconds>
    Cache-Control: no-cache
    Cache-Control: no-store
    Cache-Control: no-transform  (not handled as proxy is not changing file format) '''

    cache_control_option = "None"
    min_fresh = -1
    max_stale = -1
    max_age = -1
    # print("parse_cache_control_request", cache_ctrl)
    if not cache_ctrl:
        return {
            "client_cache_control":cache_control_option,
            "client_max_age": max_age,
            "client_max_stale":max_stale,
            "client_min_fresh":min_fresh
        }
    for cache_control in cache_ctrl:
        options_pos = cache_control.find(":")
        if options_pos == -1:
            return {
                "client_cache_control":cache_control_option,
                "client_max_age": max_age,
                "client_max_stale":max_stale,
                "client_min_fresh":min_fresh
            }
        options = cache_control[options_pos+1:len(cache_control)].split(",")
        for option in options:
            option = option.strip()
            option = option.lower()
            if "no-store" in option:
                cache_control_option = "no-store"
                break
            else:
                option = option.replace(" ", "")
                pos = option.find("=")
                if "no-cache".lower() in option:
                    cache_control_option = "no-cache"
                if "min-fresh".lower() in option:
                    min_fresh = int(option[pos+1:len(option)])
                if "max-stale".lower() in option:
                    max_stale = int(option[pos+1:len(option)])
                if "max-age".lower() in option:
                    # print(option)
                    max_age = int(option[pos+1:len(option)])

    return {
        "client_cache_control":cache_control_option,
        "client_max_age": max_age,
        "client_max_stale":max_stale,
        "client_min_fresh":min_fresh
    }

def parse_cache_control_response(cache_ctrl):
    ''' Following options are present in response
    Cache-Control: must-revalidate
    Cache-Control: no-cache
    Cache-Control: no-store
    Cache-Control: no-transform (not handled as proxy is not changing file format)
    Cache-Control: public
    Cache-Control: private
    Cache-Control: proxy-revalidate
    Cache-Control: max-age=<seconds>
    Cache-Control: s-maxage=<seconds> '''

    cache_control_option = "None"
    revalidate = False
    max_age = -1

    if not cache_ctrl:
        return {
            "server_cache_control":cache_control_option,
            "server_max_age": max_age,
            "server_revalidate":revalidate,
        }
    for cache_control in cache_ctrl:
        options_pos = cache_control.find(":")
        if options_pos == -1:
            return {
                "server_cache_control":cache_control_option,
                "server_max_age": max_age,
                "server_revalidate":revalidate,
            }
        options = cache_control[options_pos+1:len(cache_control)].split(",")
        for option in options:
            option = option.replace(" ", "")
            option = option.lower()
            if "no-store".lower() in option:
                cache_control_option = "no-store"
                break
            # private for proxy is equivalent to no-store comes from the server
            elif "private".lower() in option:
                cache_control_option = "no-store"
                break
            else:
                option = option.replace(" ", "")
                pos = option.find("=")
                if "no-cache".lower() in option:
                    cache_control_option = "no-cache"
                if "max-age".lower() in option:
                    max_age = int(option[pos+1:len(option)])
                if "s-maxage".lower() in option:
                    max_age = int(option[pos+1:len(option)])
                if "public".lower() in option:
                    cache_control_option = "public"
                if "must-revalidate".lower() in option:
                    revalidate = True
                if "proxy-revalidate".lower() in option:
                    revalidate = True
    # print(cache_control_option, max_age, revalidate)
    return {
        "server_cache_control":cache_control_option,
        "server_max_age": max_age,
        "server_revalidate":revalidate,
    }

def parse_http_request(client_data):
    ''' returns a dictionary of connnection_info '''
    try:
        # parse first line like below
        # http:://127.0.0.1:20101/file_name

        lines = client_data.decode('utf-8').splitlines()
        while lines[len(lines)-1] == '':
            lines.remove('')
        first_line_tokens = lines[0].split()
        url = first_line_tokens[1]
        # get starting index of IP
        url_pos = url.find("://")

        if url_pos != -1:
            protocol = url[:url_pos]
            url = url[(url_pos+3):]
        else:
            protocol = "http"

        # get port if any
        # get url path
        port_pos = url.find(":")
        path_pos = url.find("/")
        if path_pos == -1:
            path_pos = len(url)

        # change request path accordingly
        if port_pos == -1 or path_pos < port_pos:
            server_port = 80
            server_addr = url[:path_pos]
        else:
            server_port = int(url[(port_pos+1):path_pos])
            server_addr = url[:port_pos]
            # print(socket.gethostbyname('www.google.com'))
            # print(socket.gethostbyname(server_addr))

        # check for auth
        auth_line = [line for line in lines if "Authorization" in line]
        if auth_line:
            auth_b64 = auth_line[0].split()[2].encode('utf-8')
        else:
            auth_b64 = None
        # check for cache-Control
        cache_control = [line for line in lines if "Cache-Control".lower() in line.lower()]
        dict_cache_control = parse_cache_control_request(cache_control)

        # print(server_addr, url)
        # build up request for server
        first_line_tokens[1] = url[path_pos:]
        lines[0] = ' '.join(first_line_tokens)
        client_data = "\r\n".join(lines) + "\r\n\r\n"
        try:
            server_addr = socket.gethostbyname(server_addr)
        except Exception as exception:
            print("Exception in getting hostbyname", exception)
        finally:
            connnection_info_dict = {
                "url" : url,
                "server_port" : server_port,
                "server_addr" : server_addr,
                "protocol" : protocol,
                "method" : first_line_tokens[0],
                "auth_b64" : auth_b64,
                "client_data" : client_data.encode('utf-8'),

            }

        # connnection_info_dict.update(dict_cache_control)
        return connnection_info_dict, dict_cache_control

    except Exception as exception:
        print("Exception parse_http_request:", exception)
        print("")
        return None, None


def insert_if_modified(connnection_info):
    ''' Insert If-Modified-Since header '''

    lines = connnection_info["client_data"].decode('utf-8').splitlines()
    while lines[len(lines)-1] == '':
        lines.remove('')

    header = time.strftime("%a %b %d %H:%M:%S %Y", connnection_info["last_mtime"])
    header = "If-Modified-Since: " + header
    lines.append(header)

    cl_data = "\r\n".join(lines) + "\r\n\r\n"
    connnection_info["client_data"] = cl_data.encode('utf-8')
    return connnection_info

def insert_warning_header(resp_text):
    ''' Insert Stale warning header  110'''
    # print("insert_warning_header")
    lines = resp_text.splitlines()
    while lines[len(lines)-1] == '':
        lines.remove('')
    Date = [line for line in lines if "Date" in line]
    date = ""
    if not Date:
        print("No Date")
    else:
        pos = Date[0].find(":")
        date = Date[0][pos:]
        print("date:", date)

    header = "Warning: " + "110 - Response is Stale" + date
    lines.append(header)
    resp_text = "\r\n".join(lines) + "\r\n\r\n"
    return resp_text

def send_cached_file(client_socket, client_addr, connnection_info):
    print("returning cached file %s to %s" % (connnection_info["cache_path"], str(client_addr)))
    try:
        get_lock(connnection_info["url"])
        chunk_buf = b""
        resp_text = ""
        body_to_follow = False
        file = open(connnection_info["cache_path"], 'rb')
        while not body_to_follow:
            chunk = file.read(BUFFER_SIZE)
            chunk_buf += chunk
            if CRLF2 in chunk_buf:
                # print("send_cached_file:", chunk_buf)
                body_to_follow = True
                chunk_buf2 = chunk_buf.split(CRLF2)
                resp_text += chunk_buf2[0].decode("utf-8")+ "\r\n\r\n"
                if connnection_info["stale"]:
                    resp_text = insert_warning_header(resp_text)
                chunk = chunk_buf2[1]
                if resp_text:
                    # print(resp_text)
                    # print(chunk)
                    client_socket.send(resp_text.encode("utf-8"))
        while chunk:
            client_socket.send(chunk)
            chunk = file.read(BUFFER_SIZE)
        file.close()
        release_lock(connnection_info["url"])
        return True
    except Exception as e:
        print("Exception send_cached_file:", e)
        return False
def is_cached_send(client_socket, client_addr, connnection_info):
    validation_needed = connnection_info["validation_needed"]
    last_mtime = connnection_info["last_mtime"]
    cached_send = False
    if last_mtime is not None and validation_needed is False:
        print("entry in cache and no validation")
        cached_send = send_cached_file(client_socket, client_addr, connnection_info)
        if cached_send:
            client_socket.close()
            return True
    return False

def handle_get_req(client_socket, client_addr, connnection_info):
    ''' Handle get request '''
    try:
        # client_data = connnection_info["client_data"]
        caching_needed = connnection_info["caching_needed"]
        # validation_needed = connnection_info["validation_needed"]
        cache_path = connnection_info["cache_path"]
        last_mtime = connnection_info["last_mtime"]
        if is_cached_send(client_socket, client_addr, connnection_info):
            return
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.connect((connnection_info["server_addr"],
                                   connnection_info["server_port"]))
        except socket.error:
            print(socket.error)
            client_socket.send(("HTTP/1.0 504 Gateway timeout\r\n").encode('utf-8'))
            client_socket.send(("\r\n\r\n").encode('utf-8'))
            server_socket.close()
            client_socket.close()
            return
        server_socket.send(connnection_info["client_data"])
        body_to_follow = False
        reply_text = ""
        reply_buf = None
        while not body_to_follow:
            reply = server_socket.recv(BUFFER_SIZE)
            if reply_buf is None:
                reply_buf = reply
            else:
                reply_buf += reply
            if CRLF2 in reply_buf:
                body_to_follow = True
                reply_buf2 = reply_buf.split(CRLF2)
                reply_text += reply_buf2[0].decode("utf-8")+ "\r\n\r\n"
                reply = reply_buf2[1]
        if "Cache-control".lower() in reply_text.lower():
            lines = reply_text.splitlines()
            while lines[len(lines)-1] == '':
                lines.remove('')
            cache_control = [line for line in lines if "Cache-Control".lower() in line.lower()]
            dict_cache_control = parse_cache_control_response(cache_control)
            if "no-store" in dict_cache_control["server_cache_control"]:
                caching_needed = False
                connnection_info["caching_needed"] = False
                connnection_info["last_mtime"] = None
                connnection_info["cache_path"] = None
            else:
                get_lock(connnection_info["url"])
                update_cache_options_in_msg_log(connnection_info["url"],
                                                client_addr, dict_cache_control)
                release_lock(connnection_info["url"])
        if last_mtime and "304 Not Modified" in reply_text:
            print("received 304")
            send_cached_file(client_socket, client_addr, connnection_info)
        else:
            if reply_buf:
                client_socket.send(reply_buf)
            if caching_needed:
                print("caching file while serving %s to %s" % (cache_path, str(client_addr)))
                get_space_for_cache()
                get_lock(connnection_info["url"])
                file = open(cache_path, "wb+")
                file.write(reply_buf)
                reply = server_socket.recv(BUFFER_SIZE)
                while reply:
                    client_socket.send(reply)
                    file.write(reply)
                    reply = server_socket.recv(BUFFER_SIZE)
                file.close()
                release_lock(connnection_info["url"])
                client_socket.send(("\r\n\r\n").encode('utf-8'))
            else:
                print("without caching serving %s to %s" % (cache_path, str(client_addr)))
                reply = server_socket.recv(BUFFER_SIZE)
                while reply:
                    client_socket.send(reply)
                    reply = server_socket.recv(BUFFER_SIZE)
                client_socket.send(("\r\n\r\n").encode('utf-8'))

        server_socket.close()
        client_socket.close()
        return

    except Exception as exception:
        server_socket.close()
        client_socket.close()

        print("Exception handle_get_req", exception)
        # print(reply)
        # sys.exit()
        return


def handle_post_req(client_socket, client_addr, connnection_info):
    ''' Handle Post request '''
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((connnection_info["server_addr"], connnection_info["server_port"]))
        server_socket.send(connnection_info["client_data"])

        while True:
            reply = server_socket.recv(BUFFER_SIZE)
            if len(reply):
                client_socket.send(reply)
            else:
                break

        server_socket.close()
        client_socket.close()
        return

    except Exception as exception:

        server_socket.close()
        client_socket.close()
        print("Exception Serv Post", exception)
        return


def is_blocked_domain(connnection_info):
    ''' check is server is part of blocked domain and if so if auth info matches that of
     previleged user '''
    # print("is_blocked_domain", connnection_info["auth_b64"], previleged_users)
    if not (connnection_info["server_addr"] + ":" + str(connnection_info["server_port"])) in blocked_domains:
        return False
    if not connnection_info["auth_b64"]:
        return True
    if connnection_info["auth_b64"] in previleged_users:
        return False
    return True



def handle_http_request(client_socket, client_addr, client_data):
    ''' Thread function to handle single http request '''

    # print("handle_http_request:", client_addr[1])
    if (client_addr[1] < MIN_CLIENT_PORT or client_addr[1] > MAX_CLIENT_PORT):
        print("Proxy serves clients running at ports from", MIN_CLIENT_PORT, "to", MAX_CLIENT_PORT)
        client_socket.send(("HTTP/1.0 400 Bad Request\r\n").encode('utf-8'))
        client_socket.send(("\r\n\r\n").encode('utf-8'))
        client_socket.close()
        print(client_addr, "closed")
        return

    connnection_info, dict_cache_control = parse_http_request(client_data)

    if not connnection_info:
        print("no connnection_info")
        client_socket.close()
        return

    isb = is_blocked_domain(connnection_info)
    if isb:
        print("Block status : ", isb)

    if isb:
        client_socket.send(("HTTP/1.0 401 UnAuthorised\r\n").encode('utf-8'))
        client_socket.send(("Content-Length: 11\r\n").encode('utf-8'))
        client_socket.send(("\r\n").encode('utf-8'))
        client_socket.send(("UnAuthorised\r\n").encode('utf-8'))
        client_socket.send(("\r\n\r\n").encode('utf-8'))

    elif connnection_info["method"] == "GET":
        connnection_info = get_cache_connnection_info(client_addr,
                                                      connnection_info, dict_cache_control)
        connnection_info["validation_needed"] = False
        connnection_info["stale"] = False
        if connnection_info["last_mtime"]:
        #     print("Last mtime:", time.mktime(connnection_info["last_mtime"]))
            validation_needed, stale = is_validation_needed(connnection_info["url"],
                                                            connnection_info["last_mtime"])
            connnection_info["stale"] = stale
            if  validation_needed is True:
                connnection_info["validation_needed"] = True
                connnection_info = insert_if_modified(connnection_info)
        handle_get_req(client_socket, client_addr, connnection_info)

    elif connnection_info["method"] == "POST":
        handle_post_req(client_socket, client_addr, connnection_info)

    client_socket.close()
    print(client_addr, "closed")
    print("")




# This funciton initializes http proxy socket and starts listening.
# When connection request is made, a new thread is created to serve the request
def proxy_server_main():

    # Initialize socket
    try:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind(('', PROXY_PORT))
        proxy_socket.listen(MAX_CONNECTIONS)

        print("Serving HTTP proxy on %s port %s ..." % (
            str(proxy_socket.getsockname()[0]),
            str(proxy_socket.getsockname()[1])
            ))

    except Exception as e:
        print("Error in starting proxy server ...")
        print("Exception:proxy_server_main", e)
        proxy_socket.close()
        raise SystemExit


    # Main Proxy loop
    while True:
        try:
            client_socket, client_addr = proxy_socket.accept()
            client_data = client_socket.recv(BUFFER_SIZE)

            print("")
            print("%s - - [%s] \"%s\"" % (
                str(client_addr),
                str(datetime.datetime.now()),
                client_data.splitlines()[0]
                ))

            _thread.start_new_thread(
                handle_http_request,
                (
                    client_socket,
                    client_addr,
                    client_data
                )
            )

        except KeyboardInterrupt:
            client_socket.close()
            proxy_socket.close()
            print("\nProxy server shutting down ...")
            break


msg_logs = {}
locks = {}
proxy_init()
proxy_server_main()
