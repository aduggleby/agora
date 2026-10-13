"use strict";
(() => {
  // scripts/ts/share-landing-designer.ts
  (() => {
    const form = document.getElementById("share-template-form");
    if (!form) return;
    const currentScript = document.currentScript;
    const initialBackgroundUrl = currentScript?.dataset.initialBackgroundUrl || "";
    const titleInput = form.querySelector("[data-template-title]");
    const h1Input = form.querySelector("[data-template-h1]");
    const descriptionInput = form.querySelector("[data-template-description]");
    const backgroundFileInput = form.querySelector("[data-template-background-file]");
    const backgroundUploadIdInput = form.querySelector("[data-template-background-upload-id]");
    const backgroundColorHexInput = form.querySelector("[data-template-background-color-hex]");
    const containerPositionInput = form.querySelector("[data-template-container-position]");
    const containerPositionSelect = form.querySelector("[data-template-container-position-select]");
    const backgroundColorModeInput = form.querySelector("[data-template-background-color-mode]");
    const backgroundColorInput = form.querySelector("[data-template-background-color]");
    const backgroundColorWrap = form.querySelector("[data-template-background-color-picker-wrap]");
    const draftShareIdInput = form.querySelector("[data-draft-share-id]");
    const uploadDropzone = form.querySelector("[data-template-upload-dropzone]");
    const uploadPick = form.querySelector("[data-template-upload-pick]");
    const uploadStatus = form.querySelector("[data-template-upload-status]");
    const previewSubtitle = document.querySelector("[data-share-preview-subtitle]");
    const previewH1 = document.querySelector("[data-share-preview-h1]");
    const previewDescription = document.querySelector("[data-share-preview-description]");
    const previewSurface = document.querySelector("[data-preview-surface]");
    const previewWrapper = document.querySelector("[data-preview-wrapper]");
    if (!titleInput || !h1Input || !descriptionInput || !backgroundFileInput || !backgroundUploadIdInput || !backgroundColorHexInput || !containerPositionInput || !containerPositionSelect || !backgroundColorModeInput || !backgroundColorInput || !backgroundColorWrap || !draftShareIdInput || !uploadDropzone || !uploadPick || !uploadStatus) {
      return;
    }
    const defaultBackgroundColor = "#faf7f2";
    let uploadedPreviewUrl = initialBackgroundUrl;
    const allPositionClasses = [
      "items-start",
      "items-center",
      "items-end",
      "justify-start",
      "justify-center",
      "justify-end"
    ];
    const positionClassMap = {
      top_left: ["items-start", "justify-start"],
      top_right: ["items-start", "justify-end"],
      bottom_left: ["items-end", "justify-start"],
      bottom_right: ["items-end", "justify-end"],
      center_right: ["items-center", "justify-end"],
      center_left: ["items-center", "justify-start"],
      center_top: ["items-start", "justify-center"],
      center_bottom: ["items-end", "justify-center"],
      center: ["items-center", "justify-center"]
    };
    const updatePreview = () => {
      if (previewSubtitle) {
        const subtitleText = titleInput.value || "";
        previewSubtitle.textContent = subtitleText;
        previewSubtitle.style.display = subtitleText ? "" : "none";
      }
      if (previewH1) previewH1.textContent = h1Input.value || "A file was shared with you";
      if (previewDescription) previewDescription.textContent = descriptionInput.value || "";
      if (previewSurface) {
        previewSurface.style.backgroundColor = backgroundColorModeInput.value === "custom" ? backgroundColorInput.value : defaultBackgroundColor;
        previewSurface.style.backgroundImage = uploadedPreviewUrl ? `url(${uploadedPreviewUrl})` : "";
        previewSurface.style.backgroundSize = uploadedPreviewUrl ? "cover" : "";
        previewSurface.style.backgroundPosition = uploadedPreviewUrl ? "center" : "";
      }
      if (previewWrapper) {
        previewWrapper.classList.remove(...allPositionClasses);
        const next = positionClassMap[containerPositionInput.value] || positionClassMap.center;
        previewWrapper.classList.add(...next);
      }
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
      formData.append("draftShareId", draftShareIdInput.value);
      fetch("/api/uploads/stage-template-background", { method: "POST", body: formData }).then((response) => response.ok ? response.json() : Promise.reject()).then((json) => {
        backgroundUploadIdInput.value = json.uploadId || "";
        if (uploadedPreviewUrl && uploadedPreviewUrl.startsWith("blob:")) {
          URL.revokeObjectURL(uploadedPreviewUrl);
        }
        uploadedPreviewUrl = URL.createObjectURL(file);
        setStatus(`Uploaded: ${json.fileName || file.name}`, false);
        updatePreview();
      }).catch(() => setStatus("Upload failed.", true));
    };
    const refreshColorMode = () => {
      const isCustom = backgroundColorModeInput.value === "custom";
      backgroundColorWrap.classList.toggle("hidden", !isCustom);
      backgroundColorHexInput.value = isCustom ? backgroundColorInput.value : "";
      updatePreview();
    };
    [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener("input", updatePreview));
    backgroundColorModeInput.addEventListener("change", refreshColorMode);
    backgroundColorInput.addEventListener("input", refreshColorMode);
    containerPositionSelect.addEventListener("change", () => {
      containerPositionInput.value = containerPositionSelect.value || "center";
      updatePreview();
    });
    uploadPick.addEventListener("click", () => backgroundFileInput.click());
    backgroundFileInput.addEventListener("change", () => {
      const file = backgroundFileInput.files?.[0];
      if (file) stageBackground(file);
    });
    uploadDropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      uploadDropzone.classList.add("ring-2", "ring-terra/40");
    });
    uploadDropzone.addEventListener("dragleave", () => uploadDropzone.classList.remove("ring-2", "ring-terra/40"));
    uploadDropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      uploadDropzone.classList.remove("ring-2", "ring-terra/40");
      const file = event.dataTransfer?.files?.[0];
      if (file) stageBackground(file);
    });
    refreshColorMode();
    if (initialBackgroundUrl || backgroundUploadIdInput.value) {
      setStatus("Uploaded background image selected.", false);
    }
  })();
})();
//# sourceMappingURL=share-landing-designer.js.map
