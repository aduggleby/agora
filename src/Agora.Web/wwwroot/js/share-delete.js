"use strict";
(() => {
  // scripts/ts/share-delete.ts
  (() => {
    const dialog = document.querySelector("[data-share-delete-dialog]");
    if (!dialog) return;
    const nameNode = dialog.querySelector("[data-share-delete-name]");
    const cancelButton = dialog.querySelector("[data-share-delete-cancel]");
    const confirmButton = dialog.querySelector("[data-share-delete-confirm]");
    let pendingForm = null;
    document.querySelectorAll("[data-share-delete-trigger]").forEach((button) => {
      button.addEventListener("click", () => {
        const form = button.closest("[data-share-delete-form]");
        if (!form) return;
        pendingForm = form;
        if (nameNode) {
          nameNode.textContent = form.getAttribute("data-share-name") || "";
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
//# sourceMappingURL=share-delete.js.map
