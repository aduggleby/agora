"use strict";
(() => {
  // Scripts/share-template-designer-legacy.ts
  (() => {
    const form = document.getElementById("share-template-form");
    if (!form) return;
    const titleInput = form.querySelector("[data-template-title]");
    const h1Input = form.querySelector("[data-template-h1]");
    const descriptionInput = form.querySelector("[data-template-description]");
    const backgroundFileInput = form.querySelector("[data-template-background-file]");
    const backgroundUploadIdInput = form.querySelector("[data-template-background-upload-id]");
    const backgroundColorHexInput = form.querySelector("[data-template-background-color-hex]");
    const backgroundColorModeInput = form.querySelector("[data-template-background-color-mode]");
    const backgroundColorInput = form.querySelector("[data-template-background-color]");
    const backgroundColorWrap = form.querySelector("[data-template-background-color-picker-wrap]");
    const draftShareIdInput = form.querySelector("[data-draft-share-id]");
    const uploadDropzone = form.querySelector("[data-template-upload-dropzone]");
    const uploadPick = form.querySelector("[data-template-upload-pick]");
    const uploadStatus = form.querySelector("[data-template-upload-status]");
    const previewTitle = document.querySelector("[data-preview-title]");
    const previewH1 = document.querySelector("[data-preview-h1]");
    const previewDescription = document.querySelector("[data-preview-description]");
    const previewCard = document.querySelector("[data-preview-card]");
    if (!titleInput || !h1Input || !descriptionInput || !backgroundFileInput || !backgroundUploadIdInput || !uploadDropzone || !uploadPick || !uploadStatus || !previewTitle || !previewH1 || !previewDescription || !previewCard) {
      return;
    }
    const allowedExtensions = /* @__PURE__ */ new Set([".jpg", ".jpeg", ".png", ".svg", ".webp"]);
    let uploadedPreviewUrl = "";
    const updatePreview = () => {
      previewTitle.textContent = titleInput.value || "Shared file";
      previewH1.textContent = h1Input.value || "A file was shared with you";
      previewDescription.textContent = descriptionInput.value || "";
      const customBackgroundColor = backgroundColorModeInput && backgroundColorInput && backgroundColorModeInput.value === "custom" ? backgroundColorInput.value : "";
      previewCard.style.backgroundColor = customBackgroundColor || "";
      previewCard.style.backgroundImage = uploadedPreviewUrl ? `url(${uploadedPreviewUrl})` : "";
    };
    const setStatus = (text, isError) => {
      uploadStatus.textContent = text;
      uploadStatus.classList.remove("text-ink-muted", "text-danger");
      uploadStatus.classList.add(isError ? "text-danger" : "text-ink-muted");
    };
    const stageBackground = (file) => {
      setStatus("Uploading background image...", false);
      const formData = new FormData();
      formData.append("file", file, file.name);
      if (draftShareIdInput?.value) {
        formData.append("draftShareId", draftShareIdInput.value);
      }
      fetch("/api/uploads/stage-template-background", { method: "POST", body: formData }).then((response) => response.ok ? response.json() : Promise.reject(new Error("Upload failed"))).then((json) => {
        const backgroundUploadId = json.uploadId || "";
        backgroundUploadIdInput.value = backgroundUploadId;
        if (uploadedPreviewUrl) URL.revokeObjectURL(uploadedPreviewUrl);
        uploadedPreviewUrl = URL.createObjectURL(file);
        setStatus(backgroundUploadId ? `Uploaded: ${json.fileName || file.name}` : "Upload failed.", !backgroundUploadId);
        updatePreview();
      }).catch(() => {
        setStatus("Upload failed.", true);
      });
    };
    const handleSelectedFiles = (files) => {
      const list = Array.from(files || []);
      if (!list.length) return;
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
      stageBackground(file);
    };
    [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener("input", updatePreview));
    if (backgroundColorModeInput && backgroundColorInput && backgroundColorHexInput) {
      const refreshColorMode = () => {
        const isCustom = backgroundColorModeInput.value === "custom";
        backgroundColorWrap?.classList.toggle("hidden", !isCustom);
        backgroundColorHexInput.value = isCustom ? backgroundColorInput.value : "";
        updatePreview();
      };
      backgroundColorModeInput.addEventListener("change", refreshColorMode);
      backgroundColorInput.addEventListener("input", refreshColorMode);
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
    if (backgroundUploadIdInput.value) {
      setStatus("Uploaded background image selected.", false);
    }
    updatePreview();
  })();
})();
//# sourceMappingURL=share-template-designer-legacy.js.map
