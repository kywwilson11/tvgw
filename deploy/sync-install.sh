#!/bin/bash
# Replace /opt/tvgw/src with the tree this script sits in and install it, under the install lock, then
# run the command given (the CI hardware suite) from /opt/tvgw/src while still holding it:
#   sudo deploy/sync-install.sh [command...]
# The CI hardware job runs it from its checkout; `make deploy` rsyncs the working tree to a staging copy
# on the Pi and runs it from there. The copy into /opt/tvgw/src is what must not overlap a running
# install: an rsync --delete under a running install.sh left the gateway built from two trees, and a
# suite run after the lock was released checked the gateway against whichever tree was there by then.
set -euo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
DEST=/opt/tvgw/src
install -d -m 755 /run/tvgw
exec 8>/run/tvgw/install.lock
flock -w 600 8 || { echo "tvgw: another install is running" >&2; exit 1; }
[ "$SRC" = "$DEST" ] || rsync -a --delete --exclude-from="$SRC/deploy/rsync.exclude" "$SRC/" "$DEST/"
# install.sh takes the lock on the descriptor it inherits, which this open file already holds
(cd "$DEST/deploy" && TVGW_INSTALL_LOCKED=1 ./install.sh)
[ $# -eq 0 ] || { cd "$DEST" && "$@"; }
