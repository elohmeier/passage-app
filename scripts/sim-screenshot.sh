#!/bin/sh
# Usage: run-sim.sh <screenshot-name> [launch args...]
set -e
cd "$(dirname "$0")/.."
mkdir -p .build/shots
UDID=${SIM_UDID:-$(cat .build/sim-udid 2>/dev/null || xcrun simctl list devices booted -j | python3 -c "import json,sys; print([d['udid'] for r in json.load(sys.stdin)['devices'].values() for d in r][0])")}
name=$1; shift
if ! log=$(xcodebuild -project Passage.xcodeproj -scheme Passage -destination "id=$UDID" -derivedDataPath .build/xcode-sim build CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual -quiet 2>&1); then
    echo "$log" | grep -E "error:" | sort -u
    exit 1
fi
xcrun simctl install $UDID .build/xcode-sim/Build/Products/Debug-iphonesimulator/Passage.app
xcrun simctl terminate $UDID de.nerdworks.passage 2>/dev/null || true
xcrun simctl launch $UDID de.nerdworks.passage "$@" >/dev/null
sleep ${WAIT:-4}
xcrun simctl io $UDID screenshot .build/shots/$name.png >/dev/null 2>&1
echo .build/shots/$name.png
