# Mac app documentation images

These images use staged sample content, never a live account, share URL, authorization code or state value.

- `tray-menu.png`: documentation-only menu preview populated from the app's actual `NSMenu` entries. It is a rendered preview, not a desktop screenshot.
- `image-editor.png`: the actual SwiftUI/AppKit editor rendered with a synthetic capture and annotations.
- `settings.png`: the implemented SwiftUI/AppKit Settings view rendered with the fixture server `files.example.com` and fixture account `alex@example.com`, including the independent shortcut recorders and expiry controls.
- `approval.png`: browser screenshot of the server's `Authorize.cshtml` form and compiled stylesheet with sample account/device values; hidden fields are removed and form actions are disabled. Generated with `clients/macos/AgoraCapture/Tools/render-approval-preview.py`.
- `approval-confirmation.png`: browser screenshot of the app's actual `CallbackPage` HTML generator, including its locally bundled fonts. No callback query is needed.

Generate native views and callback HTML with the built app's `--render-previews <directory>` option. Generate authorization HTML with `python3 clients/macos/AgoraCapture/Tools/render-approval-preview.py <directory>`, then capture the rendered pages in a browser. The staged tray menu is intentionally labeled as a preview in the main README.
