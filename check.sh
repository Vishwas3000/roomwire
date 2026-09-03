#!/bin/sh
# Both implementations, held to one contract. Run from the repo root.
set -e
cd "$(dirname "$0")"
./swift/check.sh

# :transport needs an Android SDK to configure at all. ANDROID_HOME if it is
# set, else the two places macOS actually puts one. Without either, the Android
# half is skipped and *says* it was skipped, rather than quietly reporting a
# green run over half the code.
if [ -z "$ANDROID_HOME" ]; then
    for sdk in "$HOME/Library/Android/sdk" /opt/homebrew/share/android-commandlinetools; do
        if [ -d "$sdk/platforms" ]; then
            ANDROID_HOME="$sdk"
            export ANDROID_HOME
            break
        fi
    done
fi

( cd kotlin && ./gradlew --quiet :protocol:test --console=plain )
if [ -n "$ANDROID_HOME" ]; then
    ( cd kotlin && ./gradlew --quiet :transport:testDebugUnitTest --console=plain )
else
    echo "check.sh: no Android SDK, so :transport was not built. Set ANDROID_HOME to include it."
fi

echo "roomwire: both implementations agree with protocol/"
