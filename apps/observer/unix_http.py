import http.client, json, os, socket, stat
SOCKET='/opt/awema-jury/run/demo.sock'
class LocalHTTP(http.client.HTTPConnection):
    def connect(self):
        if not stat.S_ISSOCK(os.lstat(SOCKET).st_mode):raise ValueError('not_socket')
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout);self.sock.connect(SOCKET)
def request(path,data=None,headers=None,timeout=5):
    c=LocalHTTP('localhost',timeout=timeout)
    try:
        c.request('GET' if data is None else 'POST',path,None if data is None else json.dumps(data,ensure_ascii=False).encode(),headers or {})
        r=c.getresponse();body=r.read(100000)
        return r.status,json.loads(body),dict(r.getheaders())
    finally:c.close()
