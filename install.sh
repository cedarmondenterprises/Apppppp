#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "ERROR on line ${LINENO}; no running services changed." >&2' ERR
[ "$(id -u)" -eq 0 ] || { echo 'Run with sudo bash'; exit 1; }
PREFIX=/opt/yakmobile-v2-bridge
COMMIT=f20f4c6818b40904654381d2df471c0a22b87d6a
RAW="https://raw.githubusercontent.com/yaklang/yaklang/$COMMIT/common/yakgrpc/yakgrpc.proto"
SOURCEDIR="$(cd "$(dirname "$0")" && pwd)"
test -f "$SOURCEDIR/bridge.py"
command -v python3 >/dev/null
command -v curl >/dev/null
install -d -m 0755 "$PREFIX/protos"
install -m 0644 "$SOURCEDIR/bridge.py" "$PREFIX/bridge.py"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" -q install --disable-pip-version-check 'grpcio>=1.60,<1.90' 'grpcio-tools>=1.60,<1.90' 'protobuf>=5,<7'
# Pin to the build's exact Yaklang Git SHA. Never silently substitute main.
curl --fail --location --show-error --retry 3 --max-time 60 "$RAW" -o "$PREFIX/protos/yakgrpc.proto"
test "$(wc -c < "$PREFIX/protos/yakgrpc.proto")" -gt 10000 || { echo 'Downloaded proto unexpectedly small'; exit 1; }
# grpc_tools supplies official google protobuf imports. Fail closed on other imports.
python3 - "$PREFIX/protos/yakgrpc.proto" <<'PY'
import re,sys
s=open(sys.argv[1],encoding='utf8').read()
imports=re.findall(r'^\s*import\s+(?:public\s+|weak\s+)?"([^"]+)"',s,re.M)
unsupported=[v for v in imports if not v.startswith('google/protobuf/')]
if unsupported: raise SystemExit('Additional proto imports need review: '+str(unsupported))
print('Protocol imports:',imports)
PY
"$PREFIX/venv/bin/python" -m grpc_tools.protoc -I"$PREFIX/protos" -I"$PREFIX/venv/lib/python$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/grpc_tools/_proto" --python_out="$PREFIX/protos" "$PREFIX/protos/yakgrpc.proto"
"$PREFIX/venv/bin/python" "$PREFIX/bridge.py" --command doctor
printf '\nSUCCESS: Yaklang gRPC read-only compatibility probe installed at %s\n' "$PREFIX"
printf 'Try: sudo %s/venv/bin/python %s/bridge.py --command catalogue\n' "$PREFIX" "$PREFIX"
printf 'NO changes to systemd, Cloudflare, PataPesa or mobile app.\n'
