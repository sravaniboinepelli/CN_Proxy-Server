# HTTP Proxy
An HTTP proxy implemented using python socket programming with caching, blacklisting, authentication functionality

## Description
- proxy.py is the main proxy file
- Proxy runs on port 20100 and serves internal network clients running on ports 20000-20099. It allows access to internal servers running on ports 20101-20200 and external domains too.
- Proxy works as a middleman between the server and client does caching, authentication, etc
- Only GET and POST requests are handled.
- blacklist.txt file holds the internal or external server domains that are blocked in CIDR format.
- auth_file.txt holds the user, passwords of previleged users that are allowed to access blocked domains.

## Features (cas I probably will forget)
- Receives the request from client and passes it to the server after necessary parsing.
- Threaded proxy server is hence able to handle many requests at the same time.
- If a url is requested 3 times within a 5 minute time period, then the proxy server caches that request based on cache-control Header in request or response. Cache-control directives supported are no-store no-cache, max-age, min-fresh, max-stale in client request and no-store no-cache, public, private, s-maxage, proxy-revalidate in server response.
- To maintain integrity, cached files are accessed by securing mutex locks.
- Cache has limited size(3 responses), so if the cache is full and proxy wants to store another response then it removes the least recently asked cached response.
- Certain servers are blacklisted so that normal users can't access it. Blacklisted servers are stored in CIDR format in blacklist.txt file.
- Special users can access blacklisted servers. They must be authenticated by HTTP Basic authentication. HTTP Basic authentication is done by proxy. Usernames and passwords of priviledged users are stored in auth_file.txt file.
- While sending Stale data in case of client request with max-stale, Waring Header with code 110-Stale Response is added
- Other errors handles are  401 UnAuthorised(when client tries to access blacklisted sites with out auth details), 400 Bad Request(when received request from clients other than the proxy supported  internal network), 504 Gateway timeout(when failed to connect with server)

## Running
- python proxy.py(python3)

## Testing
- Check 2-2 folder

### Server
- run server in /test/server directory  
- `python2 server.py 20101` to run server on port 20101  
- `bash start_servers.sh 20101 20200` to run servers on all ports from 20101 to 20110.  
This script will run servers on screens
- `bash stop_servers.sh` to stop all screen processes.

### Client

- Directory: test/client/  
python2 client.py 20000 20100 20101 this will send in loop multiple GET and POST requests to the server via the proxy mentioned
`bash start_clients.sh 20000 20010`  
will run 10 clients each sending the server at 20101 via proxy 20100 on screens
- `bash stop_clients.sh` will terminate all screens.
