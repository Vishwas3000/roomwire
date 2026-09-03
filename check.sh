#!/bin/sh
# Both implementations, held to one contract. Run from the repo root.
set -e
cd "$(dirname "$0")"
./swift/check.sh
( cd kotlin && ./gradlew --quiet :protocol:test --console=plain )
echo "roomlink: both implementations agree with protocol/"
