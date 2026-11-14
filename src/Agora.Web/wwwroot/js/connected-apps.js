"use strict";
(() => {
  // scripts/ts/connected-apps.ts
  (() => {
    const dialog = document.querySelector("[data-revoke-app-dialog]");
    if (!dialog) return;
    const nameNode = dialog.querySelector("[data-revoke-app-name]");
    const cancelButton = dialog.querySelector("[data-revoke-app-cancel]");
    const confirmButton = dialog.querySelector("[data-revoke-app-confirm]");
    let pendingForm = null;
    document.querySelectorAll("[data-revoke-app-trigger]").forEach((button) => {
      button.addEventListener("click", () => {
        const form = button.closest("[data-revoke-app-form]");
        if (!form) return;
        pendingForm = form;
        if (nameNode) {
          nameNode.textContent = form.getAttribute("data-app-name") || "";
        }
        dialog.showModal();
      });
    });
    cancelButton?.addEventListener("click", () => dialog.close());
    confirmButton?.addEventListener("click", () => {
      pendingForm?.submit();
      dialog.close();
    });
  })();
  (() => {
    const button = document.querySelector("[data-copy-agent-token]");
    const input = document.querySelector("[data-agent-token-value]");
    const status = document.querySelector("[data-copy-agent-token-status]");
    if (!button || !input || !status) return;
    button.addEventListener("click", async () => {
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(input.value);
        } else {
          input.select();
          if (!document.execCommand("copy")) throw new Error("copy failed");
        }
        status.textContent = "Copied token.";
      } catch {
        input.select();
        status.textContent = "Unable to copy automatically. Select the token and copy it manually.";
      }
    });
  })();
})();
//# sourceMappingURL=connected-apps.js.map
