"use strict";
(() => {
  // scripts/ts/template-designer-preview.ts
  (() => {
    const script = document.currentScript;
    const formId = script?.dataset.formId || "account-template-form";
    const form = document.getElementById(formId);
    if (!form) return;
    const titleInput = form.querySelector("[data-preview-title]");
    const h1Input = form.querySelector("[data-preview-h1]");
    const descriptionInput = form.querySelector("[data-preview-description]");
    const backgroundFileInput = form.querySelector("[data-preview-background-file]");
    const backgroundColorModeInput = form.querySelector("[data-preview-background-color-mode]");
    const backgroundColorInput = form.querySelector("[data-preview-background-color]");
    const backgroundColorWrap = form.querySelector("[data-preview-background-color-picker-wrap]");
    const uploadPick = form.querySelector("[data-preview-upload-pick]");
    const uploadDropzone = form.querySelector("[data-preview-upload-dropzone]");
    const uploadStatus = form.querySelector("[data-preview-upload-status]");
    const titleTarget = document.getElementById("template-preview-title") || document.querySelector("[data-share-preview-subtitle]");
    const h1Target = document.getElementById("template-preview-h1") || document.querySelector("[data-share-preview-h1]");
    const descriptionTarget = document.getElementById("template-preview-description") || document.querySelector("[data-share-preview-description]");
    const card = document.getElementById("template-preview-card") || document.querySelector("[data-preview-surface]");
    if (!titleInput || !h1Input || !descriptionInput || !backgroundFileInput || !uploadPick || !uploadDropzone || !uploadStatus || !card) return;
    const allowedExtensions = /* @__PURE__ */ new Set([".jpg", ".jpeg", ".png", ".svg", ".webp"]);
    let uploadedPreviewUrl = "";
    const setStatus = (text, isError) => {
      uploadStatus.textContent = text;
      uploadStatus.classList.remove("text-ink-muted", "text-danger", "text-sage");
      uploadStatus.classList.add(isError ? "text-danger" : "text-ink-muted");
    };
    const updatePreview = () => {
      if (titleTarget) titleTarget.textContent = titleInput.value || "Shared file";
      if (h1Target) h1Target.textContent = h1Input.value || "A file was shared with you";
      if (descriptionTarget) descriptionTarget.textContent = descriptionInput.value || "";
      const customBackgroundColor = backgroundColorModeInput && backgroundColorInput && backgroundColorModeInput.value === "custom" ? backgroundColorInput.value : "";
      card.style.backgroundColor = customBackgroundColor || "";
      card.style.backgroundImage = uploadedPreviewUrl ? `url(${uploadedPreviewUrl})` : "";
    };
    const setSelectedFile = (file) => {
      const dt = new DataTransfer();
      dt.items.add(file);
      backgroundFileInput.files = dt.files;
    };
    const handleSelectedFiles = (files) => {
      const list = Array.from(files || []);
      if (list.length === 0) return;
      if (list.length > 1) {
        setStatus("Only one image can be selected.", true);
        return;
      }
      const file = list[0];
      const ext = file.name.includes(".") ? file.name.toLowerCase().slice(file.name.lastIndexOf(".")) : "";
      if (!allowedExtensions.has(ext)) {
        setStatus("Only JPG, PNG, SVG, or WEBP files are allowed.", true);
        return;
      }
      setSelectedFile(file);
      if (uploadedPreviewUrl) URL.revokeObjectURL(uploadedPreviewUrl);
      uploadedPreviewUrl = URL.createObjectURL(file);
      setStatus(`Selected: ${file.name}`, false);
      updatePreview();
    };
    [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener("input", updatePreview));
    if (backgroundColorModeInput && backgroundColorInput) {
      const refreshColorMode = () => {
        const isCustom = backgroundColorModeInput.value === "custom";
        backgroundColorWrap?.classList.toggle("hidden", !isCustom);
        backgroundColorInput.name = isCustom ? "backgroundColorHex" : "";
        if (!isCustom) backgroundColorInput.value = "#faf7f2";
        updatePreview();
      };
      backgroundColorModeInput.addEventListener("change", refreshColorMode);
      backgroundColorInput.addEventListener("input", updatePreview);
      refreshColorMode();
    }
    uploadPick.addEventListener("click", () => backgroundFileInput.click());
    backgroundFileInput.addEventListener("change", () => handleSelectedFiles(backgroundFileInput.files || []));
    uploadDropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      uploadDropzone.classList.add("ring-2", "ring-terra/40");
    });
    uploadDropzone.addEventListener("dragleave", () => uploadDropzone.classList.remove("ring-2", "ring-terra/40"));
    uploadDropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      uploadDropzone.classList.remove("ring-2", "ring-terra/40");
      handleSelectedFiles(event.dataTransfer?.files || []);
    });
    updatePreview();
  })();
})();
//# sourceMappingURL=template-designer-preview.js.map
