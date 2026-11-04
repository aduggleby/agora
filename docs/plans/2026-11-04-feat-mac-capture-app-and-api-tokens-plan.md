# Mac capture app, API tokens and capture API (plan)

Status: server API released in 0.10.0; macOS client integrated, 2026-11-04. Scope: server side (API tokens, browser sign-in for apps, capture endpoint) in this
repo, plus the macOS tray app under `clients/macos/AgoraCapture` (built on the Mac). One migration.

Decisions taken with the owner:

- The app signs in through the browser (OAuth authorization code + PKCE, loopback redirect). It never sees the password.
- Comments are callouts with an arrow whose tip is dragged onto the item.
- An upload creates an existing **temporary direct link** from the flattened, annotated PNG. Nothing else is kept on the server.
- The app lives in this repo under `clients/macos/`.
- After upload the link is copied automatically and shown in a toast with a second Copy button, auto-dismissed after 15 s.

## 1. Product

### 1.1 What the user does

1. Click the tray icon (or press a global hotkey) and choose **Capture area** or **Capture full screen**.
2. Area: the native macOS crosshair appears; drag a rectangle (Space switches to window capture). Full screen: the
   screen under the mouse is captured immediately.
3. The capture opens in the **editor**:
   - **Rectangle** tool: drag to draw an outlined rectangle.
   - **Callout** tool: click to place a text bubble, type the comment, drag the arrow tip onto the item it refers to.
   - **Colors**: ten fixed colors for rectangles. Every new rectangle takes the next color in the rotation (1st red,
     2nd orange, ..., 11th red again). Clicking a palette swatch sets which color comes next. Callouts always use one
     fixed style (near-black arrow and border, white bubble, dark text) and do not advance the rotation.
   - Select/move/resize, delete (Backspace), undo/redo (Cmd-Z / Cmd-Shift-Z).
   - Bottom bar: duration (30 min, 6 h, 1 day, 7 days; last choice remembered), **Upload** (Cmd-Enter),
     **Copy image**, **Save...**, **Cancel** (Esc).
4. On Upload the image is flattened and sent to Agora. On success:
   - the link is copied to the clipboard at once;
   - a **toast** appears near the menu bar, top right: thumbnail, the URL, the expiry ("expires in 1 day"), a **Copy link**
     button (shows "Copied" on click) and a close button. It **disappears after 15 s**; hovering pauses the timer.
   - the editor closes.
   On failure the editor stays open with the error and a Retry, so no work is lost.
5. The tray menu has **Recent links** (last 10: copy, open in browser, **Delete link** after a confirmation),
   **Settings...**, **Quit**. Default hotkeys: **Ctrl-Shift-A** capture area, **Ctrl-Shift-S** capture full screen
   (changeable in Settings).
6. Nothing is kept on the Mac after upload except the Recent links entry (URL and expiry). Save... in the editor is the
   only way to keep the image locally.

### 1.2 Connecting the app (one time)

Settings > Server URL (e.g. `https://files.example.com`) > **Connect**. The browser opens an Agora page: "Allow
**AgoraCapture on Alex's MacBook** to create temporary links in your account?" with **Approve** / **Deny**. If you are
not signed in, you sign in first and come back to this page. After Approve the browser shows "You can close this tab" and
the app shows "Connected as alex@...". **Disconnect** revokes the token on the server.

In Agora, **Settings > Connected apps** lists each device (name, connected, last used) with **Revoke**. A password
change/reset or "sign out everywhere" (security stamp rotation) disconnects all apps too. Disabling a user stops their
apps immediately.

### 1.3 What an app token can do

Only what the capture app needs: read its own account summary, create temporary direct links and delete its owner's
direct links. It cannot open the web
UI, list or change shares, or reach admin endpoints.

## 2. Authentication protocol

OAuth 2.0 authorization code flow with PKCE (RFC 7636) and a loopback redirect for native apps (RFC 8252). We
implement only this one flow, with no OAuth library and no client registration: there is a single public client
`agora-capture`.

```
App                                   Browser                              Agora
 | listen on 127.0.0.1:<random>/callback
 | verifier = 32 random bytes (b64url), challenge = b64url(SHA256(verifier)), state = 16 random bytes
 | open URL ------------------------> GET /connect/authorize?client_id=agora-capture
 |                                      &redirect_uri=http://127.0.0.1:<port>/callback
 |                                      &state=..&code_challenge=..&code_challenge_method=S256
 |                                      &device_name=AgoraCapture%20on%20Alex%27s%20MacBook
 |                                     (not signed in -> /login?returnUrl=... -> back)
 |                                     consent page, POST Approve (cookie + CSRF) ----> create pending ApiToken row
 |                                    <---------------------------- 302 redirect_uri?code=..&state=..
 | <-- GET /callback?code&state        (app answers with a small "you can close this tab" page)
 | check state
 | POST /api/v1/auth/token {grant_type: authorization_code, code, code_verifier, redirect_uri, client_id} --------->
 |                                                                    verify code (hash, unexpired, unused),
 |                                                                    SHA256(verifier) == challenge, redirect_uri equal
 | <---------------------------------- 200 {access_token: "agora_pat_...", token_type: "Bearer", token_id, email}
 | store token in Keychain
 | all API calls: Authorization: Bearer agora_pat_...
```

Rules:

- `redirect_uri` must be `http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback` (port 1024-65535). No other
  host, scheme or path. The value at exchange must equal the one at authorize byte for byte.
- `code_challenge_method` must be `S256`. `state` is required and passed back unchanged (the app checks it).
- Code: 32 random bytes, b64url, stored as SHA-256 hash, valid **10 minutes**, single use (cleared on exchange; a second
  exchange gets `invalid_grant`).
- Token: `agora_pat_` + 32 random bytes b64url. Returned **once**; stored as SHA-256 hash plus an 8-character display
  prefix. Unlike `ShareToken` (plaintext by design), API tokens and codes are **always hashed**.
- Token lifetime: no fixed expiry; revoked by the user, by security stamp rotation, or after **180 days without use**
  (idle expiry, measured from `LastUsedAtUtc`, else `ExchangedAtUtc`).
- Deny on the consent page redirects with `error=access_denied&state=...`.
- Errors from `/api/v1/auth/token` follow RFC 6749 style JSON: `{error: "invalid_grant" | "invalid_request", error_description}`
  with 400.

## 3. API contract (v1)

Full contract goes to `docs/api/v1.md` (the Mac app is built from that document alone). Summary:

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /connect/authorize` | cookie (redirects to login) | consent page, see section 2 |
| `POST /connect/authorize` | cookie + CSRF form | Approve/Deny |
| `POST /api/v1/auth/token` | none (rate-limited `AuthEndpoints`) | exchange code for token, JSON body |
| `DELETE /api/v1/auth/token` | bearer | revoke the calling token (Disconnect) |
| `GET /api/v1/me` | bearer | `{email, displayName, serverVersion, maxFileSizeBytes, directLinkDurations: ["30m","6h","1d","7d"]}` |
| `POST /api/v1/captures?duration=1d` | bearer | multipart, one part `file` (PNG or JPEG); returns `{url, token, expiresAtUtc}` |
| `DELETE /api/v1/shares/{token}` | bearer | delete one of the caller's own **direct links** early; 204, or 404 when not found / not owned / not a direct link (no difference visible), idempotent for already deleted |

- `duration` is in the query string so validation and admission run before the body is read.
- `/api/v1/*` never needs CSRF and ignores cookies.
- Status codes: 401 (missing/invalid/revoked token, body `{error}`, `WWW-Authenticate: Bearer`), 400 (bad duration,
  not an image, missing file), 413 (too large), 429 (rate limited, `Retry-After`), 503 (try again), 507 (server scratch full).
- The app uses `directLinkDurations` from `/me` and never hardcodes durations or size limits.

## 4. Server implementation

### 4.1 Domain and persistence
- `src/Agora.Domain/Entities/ApiToken.cs` (new): `Id`, `UserId` (FK, cascade delete), `ClientId`, `DeviceName`
  (max 100, trimmed, control chars removed), `TokenHash` (nullable until exchanged, unique index), `TokenPrefix`,
  `AuthCodeHash` (unique index, nullable), `AuthCodeExpiresAtUtc`, `CodeChallenge`, `RedirectUri`, `IssuedSecurityStamp`,
  `CreatedAtUtc`, `ExchangedAtUtc`, `LastUsedAtUtc`, `RevokedAtUtc`. One row covers pending (code) and active (token)
  so the code is naturally single use.
- Map in `AgoraDbContext` (Postgres context inherits). Migration only via `scripts/add-migration.sh AddApiTokens`.
- `src/Agora.Application/Utilities/ApiTokens.cs` (new): generate token/code, SHA-256 hash, PKCE S256 check
  (fixed-time comparison), redirect URI validation, display prefix.
- `src/Agora.Infrastructure/Auth/ApiTokenService.cs` (new): `CreatePendingAsync`, `ExchangeAsync`, `ValidateAsync`
  (by hash; rejects revoked, disabled user, stamp mismatch, idle expiry; writes `LastUsedAtUtc` at most every 15 min),
  `RevokeAsync`, `ListForUserAsync`.
- Cleanup: the existing recurring cleanup job also deletes pending rows past `AuthCodeExpiresAtUtc` and revoked/idle-expired
  rows older than 30 days.

### 4.2 Authentication and authorization wiring (`Program.cs`, `src/Agora.Web/Auth/`)
- `ApiTokenAuthenticationHandler` (new scheme `ApiToken`): reads `Authorization: Bearer agora_pat_...`, calls
  `ValidateAsync`, builds a principal with `NameIdentifier`, `Email`, `Name` and `agora:token_id` claims so
  `TryGetShareOwner` and every `ShareManager` call work unchanged.
- Default authenticate scheme becomes a **policy scheme** `Smart`: it forwards to `ApiToken` when the request has a
  `Bearer agora_pat_` header, otherwise to cookies. This populates `HttpContext.User` before `UseAgoraCsrf` and
  `UseRateLimiter`, so bearer callers get their own per-user rate limit partition instead of the anonymous bucket.
- Invariants, enforced with authorization policies and covered by tests:
  - `/api/v1/*` (route group) requires policy `ApiClient` = authenticated by scheme `ApiToken`.
  - The default and fallback authorization policies require scheme `Cookies`, so a token gets 401/403 on every existing
    endpoint, page, the SignalR hub and Hangfire.
- `CsrfValidation`: skip validation when the endpoint carries new `ApiEndpointMetadata` **and** the principal came from
  `ApiToken`. This check runs before the existing `RequiresHeaderCsrfToken` header check.
- `TokenRedactionEnricher` / `TokenRedaction`: redact `agora_pat_...`, `code=` and `code_verifier` values, and never
  log the `Authorization` header.

### 4.3 Sign-in round trip
- `POST /login` currently always redirects to `/`. Make it honor a `returnUrl` form field (and the login page passes
  through `?returnUrl=`) when it is a **local** path (starts with `/`, not `//` or `/\`, validated by a helper with unit
  tests), so the authorize URL with all its parameters survives login. Email confirmation and other detours drop it (acceptable).

### 4.4 Consent page
- `Pages/Connect/Authorize.cshtml(.cs)` (new, `[Authorize]` cookie): validates `client_id`, `redirect_uri`,
  `code_challenge(_method)`, `state`, `device_name`. Invalid `redirect_uri` shows an error page (never redirect to an
  unvalidated URI); other errors redirect with `error=invalid_request`. Shows the device name, signed-in email, what
  the app may do, and Approve/Deny buttons (Warm Craft styles, CSRF form). Approve calls `CreatePendingAsync` and
  redirects 302 to the loopback URI with `code` and `state`. `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.
- Check that the CSP `form-action` / redirect handling allows the 302 to `http://127.0.0.1:<port>`. A 302 after a form
  POST is not limited by `form-action` in every browser; if it is, render an "Approved, continue" page with a link.

### 4.5 Capture endpoint (`src/Agora.Web/Endpoints/ApiV1Endpoints.cs`, new)
- `POST /api/v1/captures`: same shape as `StageShareFileAsync` + `DirectLinkEndpoints.CreateAsync`, in one call:
  1. parse `duration` with `DirectLinkDurations.TryParse` (no new values);
  2. new draft id (`UploadIds`), `EnsureDraftShareAsync`, `ReserveRequestBuffer` (scratch preflight before the body);
  3. stage the `file` part via the shared staging helper (extract `StageFormFileAsync` into something both can call);
     reject anything but `image/png`/`image/jpeg` by extension and signature sniff;
  4. `ResolveDirectLinkUploadAsync`, `scratchSpace.EnsureCanAdmit(DurableDemand)`;
  5. `SealDraftForSubmissionAsync(() => CreateDirectLinkShareAsync(...))`, then `FinalizeDraftAsync` (warning on
     failure as in `DirectLinkEndpoints`); on any refusal before the seal, delete the draft;
  6. `RequestSizeLimit(MaxFileSizeBytes + 1 MB)`; response `{url = IPublicOriginProvider.ShareUrl(token), token, expiresAtUtc}`.
- Factor the shared part of `DirectLinkEndpoints.CreateAsync` into a small helper so both paths keep identical
  seal/compensation behavior.
- `GET /api/v1/me`, `DELETE /api/v1/auth/token`, `POST /api/v1/auth/token` in the same file.
- `DELETE /api/v1/shares/{token}`: look up by token and owner, require `IsDirectLink(AccessMode)`, then call the same
  ShareManager delete path the web UI's `/shares/{id}/delete` uses (so object cleanup and auditing stay identical).
- The result is an ordinary direct link: it appears in My shares with the Direct link badge, counts views, expires and
  is purged as today.

### 4.6 Settings: Connected apps
- `Pages/Account/Settings.cshtml(.cs)`: new card listing the user's active tokens (device name, prefix, connected, last
  used in browser local time) with Revoke (POST + CSRF). Empty state: "No apps connected."

### 4.7 Repo hygiene
- `.dockerignore`: add `clients/`. Make sure `Agora.slnx`, `build.csando` and the e2e/test globs do not pick up `clients/`.
- `.gitignore`: Xcode artifacts under `clients/macos` (`DerivedData/`, `*.xcuserstate`, `build/`).
- AGENTS.md: new hard requirement "API tokens and authorization codes are stored only as SHA-256 hashes (the plaintext
  rule applies only to `ShareToken`)", plus the `/api/v1` bearer-only vs cookie-only invariant and `clients/macos` in
  the layout section.

### 4.8 Tests
- Unit (`tests/Agora.Application.Tests`): PKCE check (good, wrong verifier, wrong method), redirect URI validation
  (127.0.0.1, [::1], `localhost` rejected, other paths, userinfo tricks like `http://127.0.0.1@evil`), code single use and
  expiry, token validation (revoked, disabled user, stamp rotated, idle expired), `LastUsedAtUtc` throttle, local
  `returnUrl` helper, redaction of `agora_pat_`.
- E2E (`tests/e2e/specs/api-capture.spec.ts`, Playwright `request` with `maxRedirects: 0`): sign in, GET authorize,
  POST Approve, read `code` from the `Location` header, exchange, `GET /api/v1/me`, `POST /api/v1/captures` with a PNG,
  `GET /s/{token}` returns `image/png`; token on `/api/shares` and an admin endpoint gets 401/403; a cookie-only call to
  `/api/v1/me` gets 401; second exchange of the same code fails; `DELETE /api/v1/shares/{token}` then `/s/{token}` is
  410, and deleting another user's link or a normal share gets 404; revoke in Settings then 401; password change then 401.
  Run on the postgres+s3 leg.

### 4.9 Docs
- `docs/api/v1.md`: complete contract (flow, parameters, example requests with curl, every status code and error body).
- README: "Capture app and API tokens" section; ARCHITECTURE: new entity, auth schemes, section 5 flow; CHANGELOG at release.

## 5. macOS app (`clients/macos/AgoraCapture`)

### 5.1 Stack
- Swift 6, SwiftUI with AppKit where needed, **macOS 14+**. Menu bar only (`LSUIElement`), `NSStatusItem`.
- Project generated by XcodeGen (`project.yml` committed, `.xcodeproj` ignored) to keep diffs reviewable; one
  dependency: `KeyboardShortcuts` (sindresorhus) for configurable global hotkeys. Everything else is system frameworks.
- Signing with a stable **Apple Development** identity. The Screen Recording permission is tied to the code signature, so
  ad-hoc rebuilds would ask for it again on every build. Developer ID + notarization only if it is ever shared.

### 5.2 Modules
- `Capture`: runs `/usr/sbin/screencapture` (`-i -x` for area/window, `-x -D <display>` for full screen) into a temp
  PNG; handles user cancel (no file) and missing permission (open System Settings > Privacy > Screen Recording with an
  explanation). ScreenCaptureKit is a later option if the CLI turns out to be limiting.
- `Editor`: `NSWindow` sized to the image (scaled to fit the screen), a SwiftUI canvas.
  - Model: `[Annotation]` where `Annotation = .rect(frame, colorIndex) | .callout(bubbleOrigin, text, arrowTip)`,
    coordinates in image pixels; `UndoManager` for every change.
  - Color rotation: `nextColorIndex` advances by one (mod 10) each time a rectangle is created; clicking a swatch sets
    it (and recolors the selected rectangle). Callouts have no color: near-black (`#1D1D1F`) arrow and 2 pt border,
    white bubble, dark text, a subtle shadow so they read on dark screenshots too.
  - Rectangle palette:
    `#E5322D` red, `#F7811E` orange, `#F5C400` yellow, `#3DAE2B` green, `#00A3A1` teal, `#1F7AE0` blue,
    `#5B4FE0` indigo, `#A23CC8` purple, `#E8418C` pink, `#1D1D1F` near-black.
  - Stroke 3 pt at display scale (6 px on Retina images); callout text 15 pt system font; the arrow is a line with a
    filled head from the bubble edge to the tip.
  - Export: render the image plus annotations with Core Graphics at native pixel size into PNG data (sRGB).
- `AgoraClient`: `URLSession`; `me()`, `uploadCapture(png, duration)` with progress, `deleteShare(token)`, `revoke()`. Maps 401 to "Reconnect",
  429/503/507 to a retryable message.
- `Auth`: `NWListener` on `127.0.0.1` port 0, one-shot `/callback` handler with a 5-minute timeout, PKCE + state, opens
  the authorize URL with `NSWorkspace`, exchanges the code, stores token + server URL in the **Keychain**
  (`kSecClassGenericPassword`, service `agora.capture`).
- `Toast`: a borderless non-activating `NSPanel` (floating level, all Spaces, top-right of the screen with the menu bar)
  with the thumbnail, URL, expiry, **Copy link** and close. It auto-dismisses after **15 s**, the timer pauses on hover,
  and a new upload replaces it. We use our own panel instead of `UNUserNotificationCenter` because system
  notifications cannot be dismissed on a timer and cannot reliably show an inline copy button.
- `Settings`: server URL, Connect/Disconnect + connected email, hotkeys (defaults **Ctrl-Shift-A** area,
  **Ctrl-Shift-S** full screen; free in macOS, but a global hotkey takes them from every app, hence changeable),
  default duration, launch at login (`SMAppService`).
- `RecentLinks`: last 10 `{url, token, expiresAt, createdAt}` in `UserDefaults` (no images); expired ones are dimmed.
  Delete link asks for confirmation, calls `deleteShare`, and removes the entry (also on 404).
- No image is written outside the temp directory; the temp PNG from `screencapture` is deleted when the editor closes.
- Bundle identifier **`agora.capture`**, signed with your Apple Development team.

### 5.3 Testing on the Mac
- Unit tests: color rotation (rectangles only, callouts do not advance it), PKCE/state generation, callback parsing, annotation hit-testing, export pixel size.
- Manual checklist: area, window and full-screen capture on Retina and non-Retina displays; permission prompt; connect /
  disconnect / revoke in Agora; upload of a large 5K screenshot; toast timing and hover pause; offline error and retry.

## 6. Order of work

1. Server: entity + migration, `ApiTokens` utility, `ApiTokenService`, unit tests.
2. Server: auth handler, policy scheme, authorization invariants, CSRF skip, redaction, `returnUrl`.
3. Server: consent page, token endpoint, `/me`, capture endpoint, Settings card, cleanup.
4. Server: e2e spec, `docs/api/v1.md`, README/ARCHITECTURE/AGENTS, `.dockerignore`. Independent review, commit, release,
   deploy. **The server is then ready for the app.**
5. Mac (on the Mac): scaffold, auth/connect, capture + toast with a plain upload (no editor), then the editor, settings,
   recent links.

## 7. Decisions (resolved 2026-11-04)

1. Token idle expiry: **180 days without use**.
2. Callouts: **one fixed style** (near-black arrow/border, white bubble); only rectangles rotate colors.
3. Delete from the app: **yes, in v1**, via `DELETE /api/v1/shares/{token}` (owner's direct links only).
4. Local copies: **none**; Save... in the editor only.
5. Hotkeys: **Ctrl-Shift-A** area, **Ctrl-Shift-S** full screen.
6. Bundle identifier: **`agora.capture`**, Apple Development signing.

No open questions remain.

## Client implementation progress (2026-11-04)

An initial client now exists under `clients/macos/AgoraCapture`, independently of the server work. SwiftPM and XcodeGen build definitions are included. Native capture, annotation editing/export, settings, recent links, clipboard and timed toast are implemented with demo mode enabled by default. Browser PKCE sign-in, Keychain and a client for the proposed API are implemented but not verified against a running server. See the client README for validation, known gaps, and the integration checklist. This does not mark the server implementation complete.

Initial deviations: native system fonts, two selectable hotkey presets using system Carbon APIs rather than a third-party shortcut dependency, and indeterminate upload status. Arbitrary hotkey recording and byte progress remain follow-up work. Builds default to ad-hoc signing; pass an Apple Development identity for stable capture permission.


## Client API v1 integration (2026-11-04)

Integrated with the released 0.10.0 server contract at `docs/api/v1.md` (upstream `83b5fba`). Demo mode, fake uploads and the sample capture menu are removed. Browser PKCE consent, token exchange, `/me`, multipart upload with progress, direct-link deletion and disconnect now follow the published contract. HTTP 401 deletes credentials, disconnect forgets credentials even offline, deletion accepts 204/404, and 429/503/507 offer delayed retry with annotations retained. Durations/limits are server-provided. The app was tested with 21 Swift tests, including a real loopback callback round trip; live browser consent, code exchange, Keychain persistence and account/expiry loading were verified successfully. Live upload/deletion/revocation remain manual checks. The server API was pulled without changes to its implementation.
