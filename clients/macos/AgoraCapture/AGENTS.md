# Agora Capture development

- The owner requests automatic local installation whenever a new app version is built. Use `scripts/build-app.sh`, which installs to `/Applications/Agora Capture.app` by default. Do not make the owner manually download or install each development build.
- Keep `AGORA_SKIP_INSTALL=1` available for CI or explicitly requested build-only runs.
- The owner explicitly requests exiting the existing app and restarting the newly installed copy on every update. The installer terminates AgoraCapture processes, waits for exit, installs, and opens `/Applications/Agora Capture.app`. This replaces the earlier instruction to leave running editors open.
- Run the Swift tests for behavior changes before building and installing the updated app.
