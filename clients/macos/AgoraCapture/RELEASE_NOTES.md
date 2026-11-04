Restyles the browser callback page to match Agora's authorization screen.

- Cream background, Instrument Serif heading, DM Sans text and a bordered white card.
- Sky-blue Focus icon and a Return to Agora Capture button that opens the app's Settings.
- Clear approval, declined and invalid callback states; approval copy does not claim the token exchange has already succeeded.
- Fonts are bundled locally. No external assets, callback query reflection or browser referrers; responses are non-cacheable and use a restrictive Content Security Policy.
- 22 tests, including callback HTML escaping/privacy checks and a real loopback round trip.

Requires macOS 14+. The ZIP filename identifies its CPU architecture. This is an ad-hoc signed development preview, not a notarized distribution build. See the client README for building with an Apple Development identity. The server is released separately.
