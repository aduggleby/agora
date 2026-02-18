"use strict";
(() => {
  // Scripts/share-download.ts
  (() => {
    const browser = document.querySelector("[data-file-browser]");
    if (!browser) return;
    const items = Array.from(browser.querySelectorAll("[data-preview-select]"));
    const body = browser.querySelector("[data-preview-body]");
    if (!body) return;
    const renderPreviewImage = (previewImageUrl, fileName) => {
      const alt = fileName.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
      return `<div class="preview-frame"><img src="${previewImageUrl}" alt="${alt} preview" loading="lazy" /></div>`;
    };
    items.forEach((item) => {
      const openButton = item.querySelector("[data-preview-open]");
      if (!openButton) return;
      openButton.addEventListener("click", () => {
        items.forEach((node) => node.classList.remove("active"));
        item.classList.add("active");
        const previewImageUrl = item.dataset.previewImageUrl || "";
        const fileName = item.dataset.name || "File";
        body.innerHTML = renderPreviewImage(previewImageUrl, fileName);
      });
    });
  })();
})();
//# sourceMappingURL=share-download.js.map
