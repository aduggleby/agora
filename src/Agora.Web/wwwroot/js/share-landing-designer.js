"use strict";
(() => {
  // scripts/ts/page-drop.ts
  var highlightClasses = ["ring-2", "ring-terra/40"];
  var carriesFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes("Files");
  var isTextField = (target) => target instanceof HTMLElement && (target.isContentEditable || target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement && !["button", "checkbox", "color", "file", "radio", "range", "reset", "submit"].includes(target.type));
  var pad = (value) => String(value).padStart(2, "0");
  var isBackgroundImage = (file) => /\.(jpe?g|png|webp)$/i.test(file.name);
  var backgroundImageHint = "Only .jpg, .jpeg, .png or .webp images can be used as the background.";
  var namePastedFile = (file, now = /* @__PURE__ */ new Date()) => {
    if (file.name && !/^image\.[a-z0-9]+$/i.test(file.name)) return file;
    const fromType = (file.type.split("/")[1] ?? "").split("+")[0].replace(/^x-/, "");
    const extension = ((file.name ? file.name.split(".").pop() : "") || fromType || "png").toLowerCase().replace("jpeg", "jpg");
    const stamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    return new File([file], `pasted-${stamp}.${extension}`, { type: file.type, lastModified: file.lastModified });
  };
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
    document.addEventListener("paste", (event) => {
      const clipboard = event.clipboardData;
      const files = Array.from(clipboard?.files ?? []);
      if (files.length === 0) return;
      if (isTextField(event.target) && (clipboard?.types ?? []).includes("text/plain")) return;
      event.preventDefault();
      if (isEnabled()) onFiles(files.map((file) => namePastedFile(file)));
    });
  }

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
      fetch(`/api/uploads/stage-template-background?draftShareId=${encodeURIComponent(draftShareIdInput.value)}`, { method: "POST", body: formData }).then((response) => response.ok ? response.json() : Promise.reject()).then((json) => {
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
    enablePageDrop({
      dropzone: uploadDropzone,
      label: "Drop an image to use as the background",
      onFiles: (files) => {
        if (!isBackgroundImage(files[0])) {
          setStatus(backgroundImageHint, true);
          return;
        }
        stageBackground(files[0]);
      }
    });
    refreshColorMode();
    if (initialBackgroundUrl || backgroundUploadIdInput.value) {
      setStatus("Uploaded background image selected.", false);
    }
  })();
})();
//# sourceMappingURL=share-landing-designer.js.map
