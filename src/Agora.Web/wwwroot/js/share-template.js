"use strict";
(() => {
  // Scripts/share-template.ts
  (() => {
    const form = document.querySelector("[data-share-form]");
    if (!form) return;
    const summary = form.querySelector("[data-template-summary]");
    const modeInput = form.querySelector("[data-template-mode]");
    const titleInput = form.querySelector("[data-template-title]");
    const h1Input = form.querySelector("[data-template-h1]");
    const customActions = form.querySelector("[data-template-custom-actions]");
    const designerLink = form.querySelector("[data-template-designer-link]");
    if (!modeInput) return;
    const refreshSummary = () => {
      if (modeInput.value !== "per_upload") {
        if (summary) summary.textContent = "Using account default template.";
        customActions?.classList.add("hidden");
        return;
      }
      const heading = h1Input?.value || titleInput?.value || "Untitled";
      if (summary) summary.textContent = `Custom design selected: ${heading}.`;
      customActions?.classList.remove("hidden");
    };
    designerLink?.addEventListener("click", (event) => {
      if (modeInput.value !== "per_upload") {
        event.preventDefault();
      }
    });
    modeInput.addEventListener("change", refreshSummary);
    refreshSummary();
  })();
})();
//# sourceMappingURL=share-template.js.map
