from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/Rules.json":
            p = Path("rules.json")
            if not p.exists():
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"rules.json not found"}')
                return

            data = p.read_bytes() 
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            # Optional cache control if you want clients to always fetch fresh:
            # self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"Not found"}')

def run():
    server_address = ("", 5000)
    httpd = HTTPServer(server_address, SimpleHandler)
    print("Serving on port 5000...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
