import http.server
import json
import re
import subprocess
from pathlib import Path

PORT = 12423
ROOT = Path(__file__).resolve().parent

def _display_name(fname):
    """sitesrv's display_name(): strip .elf, underscores to spaces, cap first."""
    stem = fname[:-4] if fname.lower().endswith(".elf") else fname
    stem = stem.replace("_", " ")
    return stem[:1].upper() + stem[1:]

def _build_manifest():
    """Live payloads/ listing - the same JSON sitesrv serves on the console."""
    items = []
    payloads = ROOT / "payloads"
    if payloads.is_dir():
        for f in sorted(payloads.iterdir()):
            name = f.name
            if not name.lower().endswith(".elf"):
                continue                    # only ELF payloads
            if name.startswith("elfldr-ps5") or name.startswith("kexp"):
                continue                    # chain internals, not sendable cards
            items.append({
                "filename": name,
                "name": _display_name(name),
                "url": "payloads/" + name,
                "bytes": f.stat().st_size,
                "category": "PS5 Storage",
                "description": "Payload stored on this host - no internet needed to send it",
            })
    return {"source": "relapse-site", "generated": True, "payloads": items}

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.split("?")[0] == "/manifest.json":
            self._send_manifest()
            return
        super().do_GET()

    def _send_manifest(self):
        body = json.dumps(_build_manifest(), indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def cache_control(self):
        path = self.translate_path(self.path).split("?")[0]  # ignore ?v= cache busters
        if path.endswith("manifest.json"):  # generated live - handled above
            return None
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
        cc = self.cache_control()
        if cc:
            self.send_header("Cache-Control", cc)
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