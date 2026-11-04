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
})();
//# sourceMappingURL=connected-apps.js.map
