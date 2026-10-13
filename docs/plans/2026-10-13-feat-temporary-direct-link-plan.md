# Temporary direct links (plan)

Status: proposed, 2026-10-13. Scope: one feature, no migration, no new settings.

## 1. Product

A signed-in user who has staged exactly one file on the new-share page gets a second button to the left of "Create share link": **Create temporary direct link**, with a duration dropdown next to it (30 min, 6 hours, 1 day, 7 days; default 1 day, last choice remembered in the browser).

Clicking it creates the share instantly (no archive, no queue), shows the link in place and copies it to the clipboard with a "Copied to clipboard" notice. The link uses the normal `/s/{token}` format, but opening it returns the file itself (an image shows as an image, a PDF as a PDF) with no interstitial page, so it can be pasted into chats, forums or `<img src>`.

- Eligible files: anything the content policy already serves inline (raster images, common video and audio, PDF, plain text). Otherwise the button is disabled with a tooltip saying why (more than one file, uploads still running, or a file type that can only be downloaded).
- After the chosen duration the link stops working (HTTP 410) and the stored file is purged at the next cleanup run, at most 30 minutes later.
- Direct links appear in "My shares" with a **Direct link** badge and their expiry, can be deleted early, and cannot be re-enabled or password protected.
- Every view is counted as a download; no notification email is ever sent for them.
- They count toward the same scratch and size limits as normal shares.

## 2. Behaviour details

| Aspect | Decision |
| --- | --- |
| URL | `/s/{token}` with a generated token (no custom slug) |
| Response | file bytes, inline, headers from `ObjectResults.UserContent` (extension-derived type, `nosniff`, sandbox CSP; inline PDFs excepted as today) |
| Expired or deleted | 410 with the existing "This link has expired" page for browsers; same status for image embeds |
| Sub-routes (`/files`, `/preview`, `/download`, `/og-image`, `/gallery`) | unchanged: they answer 403/410 because the share allows neither preview nor zip download |
| Access mode | new `ShareAccessMode.DirectLink` stored as `direct_link` (`AccessMode` column is a string: no migration) |
| Archive | none; `ZipDiskPath` stays empty, `ZipDisplayName` = original file name |
| Notify mode | `none`, fixed |
| Views | recorded through `ShareManager.RecordDownloadAsync` for every request, authenticated or not |
| Cleanup | `CleanupExpiredSharesAsync` purges direct-link shares as soon as they are expired (other shares keep the 7-day grace for "Re-enable 24h") |
| Re-enable 24h | hidden and refused (409) for direct links |
| Show link | the created page renders a simplified card (URL, expiry, copy button); no progress UI |
| Durations | fixed set `30m`, `6h`, `1d`, `7d`; the server rejects anything else |

## 3. Implementation

### 3.1 Application / domain
- `src/Agora.Application/Models/ShareModes.cs`: add `DirectLink` to `ShareAccessMode`, parse/format `direct_link`; `AllowsPreview` and `AllowsZipDownload` stay false for it; add `IsDirectLink(mode)`.
- `src/Agora.Application/Models/DirectLinkDuration.cs` (new): the four allowed values, parse from the wire string, `TimeSpan` per value.
- `src/Agora.Application/Models/CreateShareCommand.cs`: no change; a new small record `CreateDirectLinkCommand(OwnerUserId, UploaderEmail, UploadId, DraftShareId, Duration)`.

### 3.2 ShareManager
- `CreateDirectLinkShareAsync(CreateDirectLinkCommand, ct)`:
  1. resolve the single staged upload for the draft; refuse if not exactly one or if `ContentTypePolicy.Resolve(name).Inline` is false (`UploadLimitException` kinds reused where they fit, otherwise `InvalidOperationException` mapped to 400);
  2. `scratchSpace.Reserve(DurableDemand(size))` (no archive demand);
  3. `contentStore.PersistShareFilesAsync` (same durable layout `shares/yyyy/MM/{guid}/`);
  4. under the owner lock: owner exists and is enabled, insert `Share` with `AccessMode = direct_link`, `NotifyMode = none`, `ExpiresAtUtc = now + duration`, `ZipDisplayName = file name`, one `ShareFile`; token conflict retry as in `CreateShareAsync`;
  5. on failure delete the uploaded objects (existing compensation path).
- `CleanupExpiredSharesAsync`: direct-link rows use cutoff `now`, others keep `now - 7 days`.
- `ReenableShareFor24HoursAsync`: return false for direct links.
- `UserShareSummary`: add `AccessMode` so the list can badge.

### 3.3 Endpoints (`Program.cs`, or a new `Endpoints/DirectLinkEndpoints.cs`)
- `POST /api/shares/direct-link` (authorized, `UploadEndpointMetadata(RequiresHeaderCsrfToken: true)`, JSON body `{draftShareId, uploadId, duration}`, `RequestSizeLimit` 16 KB):
  1. `EnsureDraftShareAsync` + `scratchSpace.EnsureCanAdmit(DurableDemand(size))`;
  2. `SealDraftForSubmissionAsync(owner, draft, () => CreateDirectLinkShareAsync(...))` so the existing seal/unseal semantics apply (409 when already sealed, 503 on failure with unseal);
  3. `FinalizeDraftAsync` after success;
  4. returns `{ url, token, expiresAtUtc }` (`url` from `IPublicOriginProvider.ShareUrl`).
- Stage response (`UploadStagingEndpoints`): add `directLinkEligible: bool` computed with `ContentTypePolicy`, so the browser never duplicates the allowlist.

### 3.4 Serving (`Pages/S/Index.cshtml.cs`)
- At the top of `OnGet`, after `FindByTokenAsync`: if `IsDirectLink(share.AccessMode)`:
  - expired or deleted: set 410 and render the existing expired view;
  - otherwise `await manager.RecordDownloadAsync(...)` (view count), open the single file from the object store, run `ObjectResults.UserContent(Response, stored, file.OriginalFilename).ExecuteAsync(HttpContext)` and return `new EmptyResult()`. (If a Razor page handler cannot execute an `IResult` cleanly in .NET 10, return a `FileStreamResult` and set the same headers through `ObjectResults.ApplyUserContentHeaders`.)
- `GET /api/shares/{token}` and `/og-image`: return 404 for direct links (nothing to render).

### 3.5 UI (`Pages/Shares/New.cshtml`, `scripts/ts/shares-new.ts`)
- Button row becomes `flex justify-end gap-2`: `[data-direct-link-group]` (a `select[data-direct-duration]` with the four values and a `button[data-direct-link]`, both `CompactSelect`-style tight layout) followed by the existing `[data-submit]`.
- `shares-new.ts`: keep `{fileName, sizeBytes, directLinkEligible}` per upload id (from the stage response and the server-rendered rows); `refreshState()` enables the direct button only when `uploadedIds.size === 1 && activeUploads === 0 && eligible`, otherwise sets `disabled` and a `title` explaining why (AGENTS.md rule).
- Click: `fetch('/api/shares/direct-link', {method:'POST', body: JSON})` (CSRF header added by `csrf-client`), then copy the URL with the shared clipboard helper, show a `[data-direct-link-result]` panel (URL, expiry, "Copied to clipboard" flash, a copy button for retries), clear the upload list and mint a fresh `draftShareId` so the page stays usable. Errors render the server message in the panel.
- Duration remembered in `localStorage` (`agora.directLink.duration`).
- Extract the clipboard logic from `shares-created.ts` into `scripts/ts/clipboard.ts` and reuse it on both pages.
- `Pages/Index.cshtml` (My shares): badge next to the name when `AccessMode == direct_link`, hide "Re-enable 24h" for it.
- `Pages/Shares/Created.cshtml(.cs)`: simplified card for direct links (used by "Show link").
- Rebuild JS (`node ./scripts/build-ts.mjs`) and CSS (`npm run tailwind:build`).

### 3.6 Tests
- Unit: `CreateDirectLinkShareAsync` (no `zips/` object, access mode, expiry, display name, compensation on failure, refuses two files and a `.html` file), cleanup purges an expired direct link at once while a normal expired share waits 7 days, re-enable refused, `DirectLinkDuration` parsing.
- E2E (`specs/direct-link.spec.ts`): stage one PNG, button enabled, select 30 min, click; the panel shows the URL and the copied notice (grant clipboard permissions in the Playwright context and read it back); `GET /s/{token}` returns `image/png` inline with `nosniff` and the sandbox CSP; the view appears in the download count on "My shares" with the badge; two staged files disable the button with a tooltip; `POST /api/e2e/shares/{token}/expires-in-seconds` then 410.
- Existing specs stay green (full postgres+s3 leg).

### 3.7 Docs
- README: short "Temporary direct links" section under sharing; ARCHITECTURE section 5 gets the direct-link path; CHANGELOG entry at release time.

## 4. Order of work
1. ShareModes + duration model + `CreateDirectLinkShareAsync` + cleanup/re-enable changes + unit tests.
2. Endpoint + stage-response flag + serving branch.
3. UI (new page, created page, list badge), clipboard helper, builds.
4. E2E spec, README/ARCHITECTURE.
5. Independent review, commit, then part of the next release.

## 5. Open questions
None blocking. Two defaults taken without asking: the expired state uses the existing expired page (status 410), and "Show link" for a direct link reuses the created page in a simplified form rather than a new page.
