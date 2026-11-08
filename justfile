# List recipes
default:
    @just --list

# Run the PassageKit tests on macOS (interop tests need `age` 1.3+ on PATH)
test:
    cd PassageKit && swift test

# Build the iOS app for the simulator, without signing
build:
    xcodebuild -project Passage.xcodeproj -scheme Passage \
        -destination 'generic/platform=iOS Simulator' \
        -derivedDataPath .build/xcode build CODE_SIGNING_ALLOWED=NO -quiet

# Refresh the vendored C2SP/CCTV age test vectors from a local checkout
update-testkit cctv="~/repos/github.com/C2SP/CCTV":
    rsync -a --delete --exclude SOURCE.txt {{cctv}}/age/testdata/ PassageKit/Tests/AgeCryptoTests/testkit/
    printf 'Test vectors from https://github.com/C2SP/CCTV/tree/%s/age/testdata\nThe CCTV license allows vendoring without attribution.\n' \
        "$(git -C {{cctv}} rev-parse HEAD)" > PassageKit/Tests/AgeCryptoTests/testkit/SOURCE.txt

# Build, install and launch in the booted Simulator, then screenshot to .build/shots/<name>.png.
# Debug launch args: -PassageDemo YES, -PassageRoute entry:<path>|folder:<path>|search:<q>|keys|identity|settings
screenshot name *args:
    scripts/sim-screenshot.sh {{name}} {{args}}

# Archive a Release build and upload it to App Store Connect / TestFlight (needs Xcode signed in)
testflight:
    rm -rf .build/Passage.xcarchive .build/export
    xcodebuild -project Passage.xcodeproj -scheme Passage -configuration Release -destination 'generic/platform=iOS' \
        -archivePath .build/Passage.xcarchive -derivedDataPath .build/xcode-archive archive -allowProvisioningUpdates > .build/archive.log 2>&1 \
        || (grep -E ": error: " .build/archive.log | sort -u; exit 1)
    # System PATH: Xcode's export breaks with Homebrew's rsync 3.x ("Copy failed").
    env PATH=/usr/bin:/bin:/usr/sbin:/sbin xcodebuild -exportArchive -archivePath .build/Passage.xcarchive -exportPath .build/export \
        -exportOptionsPlist Config/ExportOptions.plist -allowProvisioningUpdates
