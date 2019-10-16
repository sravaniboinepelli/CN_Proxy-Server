import sys
import os
import time
import SocketServer
import SimpleHTTPServer

if len(sys.argv) < 2:
    print("Needs one argument: server port")
    raise SystemExit

if len(sys.argv) > 2:
    cache_control = sys.argv[2]
    print cache_control
else:
    cache_control = None

PORT = int(sys.argv[1])

class HTTPCacheRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def send_head(self):
        if self.command != "POST" and self.headers.get('If-Modified-Since', None):
            filename = self.path.strip("/")
            if os.path.isfile(filename):
                a = time.strptime(time.ctime(os.path.getmtime(filename)), "%a %b %d %H:%M:%S %Y")
                b = time.strptime(self.headers.get('If-Modified-Since', None), "%a %b %d %H:%M:%S %Y")
                if a < b:
                    self.send_response(304)
                    self.end_headers()
                    return None

        return SimpleHTTPServer.SimpleHTTPRequestHandler.send_head(self)

    def end_headers(self):
        # self.send_header('Cache-control', 'public, must-revalidate, s-maxage=200')
        # self.send_header('Cache-control', 'no-store')
        # self.send_header('Cache-control', 'must-revalidate')
        # self.send_header('Cache-control', 's-maxage=60')
        if cache_control:
            self.send_header('Cache-control', cache_control)
        SimpleHTTPServer.SimpleHTTPRequestHandler.end_headers(self)

    def do_POST(self):
        self.send_response(200)
        self.send_header('Cache-control', 'no-cache')
        SimpleHTTPServer.SimpleHTTPRequestHandler.end_headers(self)

s = SocketServer.ThreadingTCPServer(("", PORT), HTTPCacheRequestHandler)
s.allow_reuse_address = True
print("Serving on port", PORT)
s.serve_forever()
