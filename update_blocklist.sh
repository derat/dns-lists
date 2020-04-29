#!/bin/sh -e

# URLs of hosts files listing zones to deny.
# Entries should be mapped to "0.0.0.0".
DENY_URLS="
  https://raw.githubusercontent.com/derat/dns-lists/master/deny-hosts
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
"

# URL of file listing regular expressions matching always-permitted zones.
ALLOW_URL=https://raw.githubusercontent.com/derat/dns-lists/master/allow-patterns

# Path where the Unbound config file will be written.
CONFIG=/etc/unbound/unbound.conf.d/blocklist.conf

dryrun=
if [ "$1" = '-n' ] || [ "$1" = '--dry-run' ]; then
  dryrun=1
elif [ "$#" -ge 1 ]; then
  echo "Usage: $0 [-n|--dry-run]" >&2
  exit 2
fi

tmpdir=$(mktemp -d --tmpdir update_blocklist.XXXXXX)
[ -z "$dryrun" ] && trap "rm -r '$tmpdir'" EXIT

allow="${tmpdir}/allow"
wget --quiet -O- "$ALLOW_URL" | grep -v '^#' >"${allow}"

# The 'server:' directive here is required.
out="${tmpdir}/out"
cat <<EOF >"$out"
# Generated by $(readlink -f $0) at $(date --rfc-3339=seconds)
server:
EOF

# Add the zones from each file. Entries start with "0.0.0.0" and are followed by
# whitespace and a hostname or domain name. Comments start with '#' and can
# apparently appear at the end of lines.
for url in $DENY_URLS; do
  echo >>"$out"
  echo "# ${url}" >>"$out"
  # The first grep skips weird entries mapping 0.0.0.0 to itself.
  wget --quiet -O- "$url" | \
    sed -nre 's/^0\.0\.0\.0\s+([-_.a-zA-Z0-9]+)(\s.*|$)/\1/p' | \
    grep -v '^0\.0\.0\.0$' | \
    grep -v --extended-regexp -f "${allow}" | \
    awk '{print "local-zone: \""$1"\" refuse"}' >>"$out"
done

if [ -n "$dryrun" ]; then
  echo "Wrote config to ${out}"
  exit 0
fi

# Validate the config, install it, and restart the daemon.
if ! err=$(unbound-checkconf "$out" 2>&1); then
  echo "${err}" >&2
  exit 1
fi
mv "$out" "$CONFIG"
kill -HUP $(cat /run/unbound.pid)
