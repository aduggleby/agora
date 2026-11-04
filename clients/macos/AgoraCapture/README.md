# Agora Capture (macOS 14+)

Native menu bar capture client for Agora API v1, integrated with the contract in `docs/api/v1.md` from server release 0.10.0. All uploads and recent links use the real server; the earlier demo mode and sample-capture menu have been removed. On upgrading, legacy demo history is removed while real history is retained.

## Build and install

Requires Xcode 16+ / Swift 6 on a Mac. There are no downloaded dependencies.

```sh
cd clients/macos/AgoraCapture
./scripts/build-app.sh
```

The script installs `/Applications/Agora Capture.app`, exits the old process, and starts the installed version. Unsaved editor contents are discarded on update. Set `AGORA_SKIP_INSTALL=1` for CI/build-only use. A unique build number and Launch Services registration refresh the app icon on updates.

For stable Screen Recording and Keychain identity, use your Apple Development identity:

```sh
CODE_SIGN_IDENTITY='Apple Development: Your Name (TEAM)' ./scripts/build-app.sh
```

The default is an ad-hoc signed local build; rebuilding may require granting permissions again. Distribution signing and notarization are not configured. XcodeGen users can generate a project from `project.yml` and choose their signing team in Xcode. Launch at login requires an installed signed app.

## Connect and capture

1. Open Settings from the menu bar. Enter your HTTPS Agora server origin and choose **Connect in browser**.
2. Sign in to Agora and approve this device. The app validates the callback and stores the issued token in Keychain. Settings shows your connected email.
3. Capture an area/window (Control-Shift-A; Space switches to window capture) or the screen under the pointer (Control-Shift-S). Alternate shortcuts are available in Settings.
4. Use rectangles and comments; comments open for inline typing. Double-click to edit again, use the blue grip to move a bubble with its arrow tip anchored, or drag its tip. Selected annotations have eight resize handles. Undo/redo, Delete, Save, Copy image and Cancel remain available locally.
5. Choose a server-supported expiry and **Share link**. The flattened native-resolution sRGB PNG uploads with progress. Success copies the real URL and displays a thumbnail toast for 15 seconds (hover pauses it).
6. Recent links keeps the last ten URLs/expiry values with Copy, Open and confirmed Delete. It never retains images. Deleting a link removes the entry on both 204 and 404.

The editor uses a slim rail, a compact native strip with close/minimize/zoom buttons, and a sky-blue action bar. Rectangle colors rotate through Red, Green, Blue, Yellow, Orange, Purple, Pink, Cyan, Brown and Black. The app icon is the sky-blue Focus mark; the menu bar mark is white without a background.

## API behavior

- Browser authorization: S256 PKCE, fresh cryptographic state/verifier, one-shot `127.0.0.1` callback on an ephemeral port, five-minute timeout and cancellation. Wrong state/duplicate parameters are rejected without consuming the flow. No client secret or password enters the app.
- `POST /api/v1/auth/token`: JSON exchange, exact redirect URI, typed bearer token response.
- `GET /api/v1/me`: account, server version, upload size and expiry choices. Choices come exclusively from the server, never hardcoded in the app. Called after connection and before upload.
- `POST /api/v1/captures?duration=...`: multipart `file` with `capture.png`; file size checked before upload. The multipart envelope is staged in a temporary file and removed afterwards, avoiding a second full-size in-memory copy. Progress distinguishes uploading from server link creation.
- `DELETE /api/v1/shares/{token}`: own direct links, 204/404 treated as removed. Errors branch on HTTP status rather than message text.
- `DELETE /api/v1/auth/token`: Disconnect always deletes local Keychain credentials, including on offline/401 failure. If server revocation cannot be confirmed, Settings explains how to revoke the device in the web UI.
- Any API 401 clears the corresponding token and offers reconnection. Cookie storage and redirects are disabled for API calls. Tokens and codes never enter logs or UserDefaults.
- 413 reports too large; 429 observes Retry-After; 503/507 offer retry after a delay. The editor remains open with all annotations intact after failure. Upload POSTs are not retried automatically, avoiding accidental duplicate links.

## Validation

```sh
CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache" swift test --disable-sandbox
# Also test a real local socket (requires loopback networking):
AGORA_TEST_LOOPBACK=1 CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache" swift test --disable-sandbox
# Render UI previews using synthetic content, without transmitting anything:
.build/debug/AgoraCapture --render-previews /absolute/output/directory
```

25 tests cover API request/response contracts, disconnect cleanup on network failure, 401 invalidation, upload multipart formatting, deletion/idempotency, retry timing, origin normalization, PKCE/callback validation, a real loopback callback round trip, image export orientation/size, resize geometry and inline editing/undo. API contract tests use an injected URLProtocol fixture, not the live server. The socket test is opt-in and was run successfully during integration.

Live verification against the selected server confirmed its documented unauthenticated 401, then successful browser consent, code exchange, Keychain persistence and authenticated `/me` account/expiry loading. Upload/deletion/revocation are covered by contract tests, but were not exercised on the live account. The server itself is unchanged by this client work and its .NET tests were not run (no local .NET SDK).

Manual follow-ups: Retina/non-Retina/multiple displays, screen permission revocation, hotkey conflicts, toast timing/hover, text overflow and accessibility polish. Arbitrary shortcut recording remains future work. Native system fonts are used. Captures/PNG export still require memory proportional to the image size; only the multipart duplicate is avoided.

The icon is generated by compiling `Tools/RenderIcon.swift` with `Sources/AgoraCapture/Branding.swift`, then running the executable to generate an iconset and converting it with `iconutil`. The resulting `Resources/AgoraCapture.icns` is bundled by both build routes.

## GitHub releases

Every push to `main` triggers `.github/workflows/capture-release.yml`: run Swift tests including real loopback sign-in, build the app on macOS, and publish a prerelease tagged `capture-v<client-version>-<short-commit>` with a ZIP and SHA-256 checksum. The filename states the runner's CPU architecture. Manual workflow dispatch can retry a release; retries replace only that release's assets. Client version lives in `VERSION`; notes live in `RELEASE_NOTES.md`. This workflow does not publish the server Docker image.

The browser callback page matches Agora's authorization page: cream/ink/terra styling, locally bundled Instrument Serif and DM Sans fonts, outcome-specific copy and a Return to Agora Capture button. The `agora-capture://auth/complete` URL opens Settings only; it carries no credentials and cannot authorize a connection. Callback responses disable caching, referrers, external resources and framing; all displayed error text is escaped. The code/state query is never echoed into the HTML. Font licenses are included in `Resources/Fonts`.

The bottom bar labels the expiry dropdown **Keep for** and places it immediately to the right of Share link. Delete removes the selected rectangle or comment (and is disabled without a selection); Cancel closes the entire capture without uploading.

A successful share closes its source editor immediately, before the thumbnail toast appears. Failed shares keep the editor and annotations open for retry.
