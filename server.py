from http.server import BaseHTTPRequestHandler, HTTPServer
import json, os, re
PORT = int(os.environ.get("PORT", 8082))
SECRETS = re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")
HARDCODED = re.compile(r"(password|passwd|secret|api_key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]", re.I)
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True})
            return
        self._json(404, {"error": "not found"})
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) if length else b"{}")
        if self.path == "/review":
            diff = body.get("diff", "")
            findings = []
            for m in SECRETS.finditer(diff):
                findings.append({"type": "secret", "match": m.group(0)[:40]})
            for m in HARDCODED.finditer(diff):
                findings.append({"type": "hardcoded_secret", "match": m.group(0)[:60]})
            self._json(200, {"score": "pass" if not findings else "warn", "findings": findings})
            return
        self._json(404, {"error": "unknown route"})
    def _json(self, code, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args, **kwargs):
        return
def main():
    HTTPServer(("", PORT), Handler).serve_forever()
if __name__ == "__main__":
    main()
