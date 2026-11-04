Native macOS menu bar capture app for Agora API v1 (server 0.10.0+).

- Area, window and full-screen capture with global shortcuts.
- Minimal editor with rectangles, inline comments, draggable arrow tips, eight resize handles and undo/redo.
- Native-resolution PNG export, Save, Copy image, Cancel and Delete controls.
- Browser sign-in with PKCE and Keychain credentials; real uploads with progress, server expiry choices, clipboard links and timed thumbnail toast.
- Recent-link deletion, disconnect, token invalidation and retry handling.
- Sky-blue Focus app icon and white menu bar icon.

Requires macOS 14+. The ZIP filename identifies its CPU architecture. This is an ad-hoc signed development preview, not a notarized distribution build. Building with your own Apple Development identity is recommended for stable Screen Recording and Keychain access; see the client README. The server is released separately.

Validation: Swift tests include API contract fixtures, image export/editing checks and a real loopback sign-in round trip. Live browser sign-in and account loading have been verified; production upload/delete/revoke are not claimed as live-tested.
