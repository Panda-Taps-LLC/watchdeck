#!/bin/bash
# Child-inheritance probe: the sandbox applied to this shell must also bind the python child.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
echo "shell: started"
exec /usr/bin/python3 "$here/probe.py" "$@"
