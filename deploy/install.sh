#!/bin/sh
# NETY installer. Run it on the Linux box you will scan from:
#
#   sudo ./install.sh
#
# It is idempotent: run it again to upgrade in place. The database and the TLS
# material in /var/lib/nety are never touched.
set -eu

BIN_SRC="${BIN_SRC:-./nety}"
BIN_DST="${BIN_DST:-/usr/local/bin/nety}"
DATA_DIR="${DATA_DIR:-/var/lib/nety}"
UNIT_SRC="${UNIT_SRC:-./nety.service}"
UNIT_DST="${UNIT_DST:-/etc/systemd/system/nety.service}"
SVC_USER="${SVC_USER:-nety}"

die() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run this as root (sudo ./install.sh)"
[ -f "$BIN_SRC" ] || die "$BIN_SRC not found; run this from the unpacked release"
[ -f "$UNIT_SRC" ] || die "$UNIT_SRC not found; run this from the unpacked release"

case "$(uname -s)" in
  Linux) ;;
  *) die "NETY scans from Linux only (found $(uname -s))" ;;
esac

echo "==> service account"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
  echo "    created $SVC_USER"
else
  echo "    $SVC_USER already exists"
fi

echo "==> data directory"
mkdir -p "$DATA_DIR"
chown "$SVC_USER:$SVC_USER" "$DATA_DIR"
chmod 700 "$DATA_DIR"

echo "==> binary"
# Replace via a temporary file so a running service is never served a
# half-written binary.
install -m 0755 "$BIN_SRC" "$BIN_DST.new"
mv -f "$BIN_DST.new" "$BIN_DST"
"$BIN_DST" version

echo "==> capabilities"
# The systemd unit grants them too; setting them on the file as well means the
# binary also works when run by hand for a quick check.
if command -v setcap >/dev/null 2>&1; then
  setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$BIN_DST"
  echo "    $(getcap "$BIN_DST")"
else
  echo "    setcap not found: install libcap2-bin, or the service will fall"
  echo "    back to connect scanning only"
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo
  echo "systemd was not found, so the service was not installed."
  echo "The binary is in place; start it by hand with:"
  echo
  echo "  sudo -u $SVC_USER $BIN_DST serve --data $DATA_DIR --listen :8443"
  echo
  exit 0
fi

echo "==> systemd unit"
install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload

FIRST_RUN=0
[ -f "$DATA_DIR/nety.db" ] || FIRST_RUN=1

systemctl enable nety >/dev/null 2>&1 || true
systemctl restart nety
sleep 2

if ! systemctl is-active --quiet nety; then
  echo
  echo "the service did not start; here is what it said:"
  journalctl -u nety -n 30 --no-pager
  exit 1
fi

echo
echo "NETY is running."
echo
systemctl --no-pager --lines=0 status nety | head -4
echo
if [ "$FIRST_RUN" = 1 ]; then
  echo "First start. The administrator password was printed once, here:"
  echo
  journalctl -u nety -n 60 --no-pager | grep -B 2 -A 4 "username:" || \
    journalctl -u nety -n 40 --no-pager | tail -20
  echo
fi
echo "Reach it on:"
ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print "  https://" a[1] ":8443/"}'
echo
echo "The certificate is self-signed. Its fingerprint is in the log:"
echo "  journalctl -u nety | grep sha256"
