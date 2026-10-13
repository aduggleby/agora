# Agora Feature Ideas (Research-Informed)

Date: 2026-02-18

## Sources Reviewed
- WeTransfer Help: Previews, transfer access modes, file requests, download verification, transfer password, recoverable expired transfers
- Dropbox Help + product pages: Dropbox Transfer, branding, password/expiry/download controls, DocSend link settings and Spaces
- pCloud Help: Public Folder with static HTML hosting and direct links, branded links, version history/rewind

Key references:
- https://help.wetransfer.com/hc/en-us/articles/29534541930770-Introduction-to-Previews
- https://help.wetransfer.com/hc/en-us/articles/32543903351442-How-to-choose-preview-only-download-only-or-preview-and-download-for-your-transfers
- https://help.wetransfer.com/hc/en-us/articles/19674802507410-Request-files
- https://help.wetransfer.com/hc/en-us/articles/26059761836306-How-to-Track-Your-Downloads-with-Download-Verification
- https://help.wetransfer.com/hc/en-us/articles/202701853-Can-I-download-a-transfer-that-expired
- https://help.dropbox.com/share/dropbox-transfer
- https://help.dropbox.com/share/sent-received-transfers
- https://help.dropbox.com/share/branded-sharing
- https://help.dropbox.com/share/link-expiration
- https://help.dropbox.com/share/dropbox-docsend-link-settings-in-content-library
- https://help.dropbox.com/plans/what-is-dropbox-docsend
- https://www.pcloud.com/help/general-help-center/what-is-the-public-folder
- https://www.pcloud.com/it/help/general-help-center/how-to-enable-branding-for-my-shared-links
- https://www.pcloud.com/features/file-versioning.html

## 7 Suggestions For Flora

1. **Direct-Open Share Modes (`preview-only`, `download-only`, `preview+download`)**
Enable sender-controlled access mode per share. This maps directly to your idea of opening files directly in-browser (without forcing ZIP download).

2. **Single-Page Site Publishing Mode**
Let uploaders publish a static mini-site from uploaded files (`index.html` + assets) at a share URL. Include sandboxing and strict content security policy.

3. **Verified Download Access (Tracked vs Restricted)**
Add optional downloader verification mode:
- tracked: anyone with link can access, but event identity is captured
- restricted: only pre-approved emails can unlock download

4. **Request Portal (Inbound Upload Collection)**
Add “request files” links so recipients upload to a controlled inbox for a share/project, with instructions and deadline.

5. **Share Recovery Window After Expiry**
Allow optional post-expiry recovery for a limited period (policy-based by size/plan), reducing accidental data loss and support tickets.

6. **Download Analytics Dashboard**
Provide per-share and global analytics: views, previews, downloads, unique recipients, geo/device summary, and “never downloaded” alerts.

7. **Versioned Shares + Safe Rewind**
Allow replacing share contents while preserving URL, with version history, rollback, and clear recipient-facing version labels.

## Quick Prioritization (Suggested)
- **Near-term (high impact, lower complexity):** 1, 3, 6
- **Mid-term:** 4, 5
- **Strategic / platform step-up:** 2, 7
