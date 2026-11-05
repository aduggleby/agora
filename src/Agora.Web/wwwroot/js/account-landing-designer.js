"use strict";
(() => {
  // scripts/ts/page-drop.ts
  var highlightClasses = ["ring-2", "ring-terra/40"];
  var carriesFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes("Files");
  var createOverlay = (label) => {
    const overlay = document.createElement("div");
    overlay.setAttribute("aria-hidden", "true");
    overlay.dataset.pageDropOverlay = "";
    overlay.className = "hidden fixed inset-0 z-50 pointer-events-none items-center justify-center bg-cream/80 p-4";
    const frame = document.createElement("div");
    frame.className = "flex h-full w-full items-center justify-center rounded-2xl border-2 border-dashed border-terra bg-terra-wash/60";
    const text = document.createElement("p");
    text.className = "font-display text-3xl text-terra";
    text.textContent = label;
    frame.appendChild(text);
    overlay.appendChild(frame);
    document.body.appendChild(overlay);
    return overlay;
  };
  function enablePageDrop(options) {
    const { dropzone, onFiles, label } = options;
    const isEnabled = options.isEnabled ?? (() => true);
    const overlay = createOverlay(label);
    let depth = 0;
    const show = (visible) => {
      overlay.classList.toggle("hidden", !visible);
      overlay.classList.toggle("flex", visible);
      highlightClasses.forEach((name) => dropzone.classList.toggle(name, visible));
    };
    const reset = () => {
      depth = 0;
      show(false);
    };
    window.addEventListener("dragenter", (event) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      depth += 1;
      show(isEnabled());
    });
    window.addEventListener("dragover", (event) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = isEnabled() ? "copy" : "none";
    });
    window.addEventListener("dragleave", (event) => {
      if (!carriesFiles(event)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) show(false);
    });
    window.addEventListener("drop", (event) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      reset();
      const files = Array.from(event.dataTransfer?.files ?? []);
      if (files.length > 0 && isEnabled()) onFiles(files);
    });
    window.addEventListener("dragend", reset);
  }

  // scripts/ts/account-landing-designer.ts
  (() => {
    const form = document.getElementById("account-template-form");
    if (!form) return;
    const currentScript = document.currentScript;
    const initialBackgroundUrl = currentScript?.dataset.initialBackgroundUrl || "";
    const titleInput = form.querySelector("[data-preview-title]");
    const h1Input = form.querySelector("[data-preview-h1]");
    const descriptionInput = form.querySelector("[data-preview-description]");
    const backgroundFileInput = form.querySelector("[data-preview-background-file]");
    const backgroundColorModeInput = form.querySelector("[data-preview-background-color-mode]");
    const backgroundColorInput = form.querySelector("[data-preview-background-color]");
    const containerPositionInput = form.querySelector("[data-preview-container-position]");
    const backgroundColorWrap = form.querySelector("[data-preview-background-color-picker-wrap]");
    const uploadPick = form.querySelector("[data-preview-upload-pick]");
    const uploadDropzone = form.querySelector("[data-preview-upload-dropzone]");
    const uploadStatus = form.querySelector("[data-preview-upload-status]");
    const subtitleTarget = document.querySelector("[data-share-preview-subtitle]");
    const h1Target = document.querySelector("[data-share-preview-h1]");
    const descriptionTarget = document.querySelector("[data-share-preview-description]");
    const previewSurface = document.querySelector("[data-preview-surface]");
    const previewWrapper = document.querySelector("[data-preview-wrapper]");
    if (!titleInput || !h1Input || !descriptionInput || !backgroundFileInput || !backgroundColorModeInput || !backgroundColorInput || !containerPositionInput || !backgroundColorWrap || !uploadPick || !uploadDropzone || !uploadStatus) {
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
    const update = () => {
      if (subtitleTarget) {
        const subtitleText = titleInput.value || "";
        subtitleTarget.textContent = subtitleText;
        subtitleTarget.style.display = subtitleText ? "" : "none";
      }
      if (h1Target) h1Target.textContent = h1Input.value || "A file was shared with you";
      if (descriptionTarget) descriptionTarget.textContent = descriptionInput.value || "";
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
    const refreshColorMode = () => {
      const isCustom = backgroundColorModeInput.value === "custom";
      backgroundColorWrap.classList.toggle("hidden", !isCustom);
      backgroundColorInput.name = isCustom ? "backgroundColorHex" : "";
      if (!isCustom) backgroundColorInput.value = "#faf7f2";
      update();
    };
    const applyFile = (file) => {
      if (uploadedPreviewUrl && uploadedPreviewUrl.startsWith("blob:")) {
        URL.revokeObjectURL(uploadedPreviewUrl);
      }
      uploadedPreviewUrl = URL.createObjectURL(file);
      uploadStatus.textContent = `Selected: ${file.name}`;
      update();
    };
    [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener("input", update));
    backgroundColorModeInput.addEventListener("change", refreshColorMode);
    backgroundColorInput.addEventListener("input", update);
    containerPositionInput.addEventListener("change", update);
    uploadPick.addEventListener("click", () => backgroundFileInput.click());
    backgroundFileInput.addEventListener("change", () => {
      const file = backgroundFileInput.files?.[0];
      if (file) applyFile(file);
    });
    enablePageDrop({
      dropzone: uploadDropzone,
      label: "Drop an image to use as the background",
      onFiles: (files) => {
        const transfer = new DataTransfer();
        transfer.items.add(files[0]);
        backgroundFileInput.files = transfer.files;
        applyFile(files[0]);
      }
    });
    let submitting = false;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (submitting) return;
      submitting = true;
      uploadStatus.textContent = "Saving template...";
      try {
        const response = await fetch(form.action, { method: "POST", body: new FormData(form) });
        if (response.redirected) {
          window.location.assign(response.url);
          return;
        }
        if (response.ok) {
          window.location.assign("/account/landing-page-designer?msg=Template%20saved");
          return;
        }
        const message = (await response.text()).trim();
        uploadStatus.textContent = message || "Saving the template failed. Please try again.";
      } catch {
        uploadStatus.textContent = "Saving the template failed. Please try again.";
      } finally {
        submitting = false;
      }
    });
    refreshColorMode();
    if (initialBackgroundUrl) {
      uploadStatus.textContent = "Uploaded background image selected.";
    }
  })();
})();
//# sourceMappingURL=account-landing-designer.js.map
