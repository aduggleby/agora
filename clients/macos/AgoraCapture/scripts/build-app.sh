#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
app_version="$(cat VERSION)"
if [[ ! "$app_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "VERSION must contain a semantic version such as 0.1.0" >&2
    exit 1
fi
export CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache"
swift build --disable-sandbox -c release
output="${1:-$PWD/build/Agora Capture.app}"
mkdir -p "$output/Contents/MacOS" "$output/Contents/Resources"
ditto Resources/Fonts "$output/Contents/Resources/Fonts"
cp Resources/AgoraCapture.icns "$output/Contents/Resources/AgoraCapture.icns"
cp .build/release/AgoraCapture "$output/Contents/MacOS/AgoraCapture"
build_version="${AGORA_BUILD_NUMBER:-$(date -u +%Y%m%d%H%M%S)}"
cat > "$output/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>AgoraCapture</string>
<key>CFBundleIdentifier</key><string>agora.capture</string>
<key>CFBundleIconFile</key><string>AgoraCapture.icns</string>
<key>CFBundleName</key><string>Agora Capture</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSUIElement</key><true/>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLName</key><string>agora.capture.return</string><key>CFBundleURLSchemes</key><array><string>agora-capture</string></array></dict></array>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $app_version" "$output/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $build_version" "$output/Contents/Info.plist"
codesign --force --sign "${CODE_SIGN_IDENTITY:--}" "$output"
echo "Built: $output"

# Local development builds install automatically unless explicitly disabled.
if [[ "${AGORA_SKIP_INSTALL:-0}" != "1" ]]; then
    install_path="/Applications/Agora Capture.app"
    # The owner requests a full app restart for every installed development build.
    running_pids="$(pgrep -x AgoraCapture || true)"
    if [[ -n "$running_pids" ]]; then
        while IFS= read -r app_pid; do
            kill -TERM "$app_pid" 2>/dev/null || true
        done <<< "$running_pids"
        for attempt in {1..50}; do
            if ! pgrep -x AgoraCapture >/dev/null; then break; fi
            sleep 0.2
        done
        if pgrep -x AgoraCapture >/dev/null; then
            echo "Agora Capture did not exit; installation stopped." >&2
            exit 1
        fi
    fi
    if [[ "$output" != "$install_path" ]]; then
        ditto "$output" "$install_path"
    fi
    codesign --verify --strict "$install_path"
    # Re-register this exact bundle so Finder sees branding changes from new builds.
    touch "$install_path"
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$install_path"
    echo "Installed: $install_path"
    open "$install_path"
    echo "Relaunched: $install_path"
fi
