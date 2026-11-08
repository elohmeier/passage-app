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
