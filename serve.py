import http.server
import re
import subprocess
from pathlib import Path

PORT = 12423
ROOT = Path(__file__).resolve().parent

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, *args):
        pass

    def cache_control(self):
        path = self.translate_path(self.path).split("?")[0]  # ignore ?v= cache busters
        if path.endswith("/"):          # HTML: always revalidate, keep fresh
            return "no-cache, must-revalidate"
        if "/offsets/" in path:         # offsets update often (daily tracker)
            return "max-age=600"
        if path.endswith(".js"):        # site code + embedded payload: stable names
            return "max-age=604800"
        if path.endswith(".elf") or path.endswith(".bin"):
            return "max-age=2592000"
        return "max-age=86400"

    def end_headers(self):
        self.send_header("Cache-Control", self.cache_control())
        super().end_headers()

def local_ip():
    try:
        output = subprocess.check_output(["hostname", "-I"], text=True, errors="ignore")
        for ip in output.split():
            if ip.startswith("192.168."):
                return ip
    except Exception:
        pass
    try:
        output = subprocess.check_output(
            ["ipconfig"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        for ip in re.findall(r"IPv4[^:]*:\s*([\d.]+)", output):
            if ip.startswith("192.168."):
                return ip
    except Exception:
        pass
    return "localhost"

if __name__ == "__main__":
    with http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as server:
        print(f"http://{local_ip()}:{PORT}/")
        server.serve_forever()