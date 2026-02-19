"use strict";
(() => {
  // scripts/ts/upload-limits.ts
  var formatLimitBytes = (bytes) => {
    if (!Number.isFinite(bytes) || bytes <= 0) return "";
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };
  var validateFileSelection = (files, limits, currentFileCount, currentTotalBytes) => {
    if (files.length === 0) return { ok: true };
    if (limits.maxFilesPerShare > 0 && currentFileCount >= limits.maxFilesPerShare) {
      return { ok: false, message: `You already have ${currentFileCount} file(s) staged \u2014 the maximum is ${limits.maxFilesPerShare} files per share.` };
    }
    if (limits.maxFilesPerShare > 0 && currentFileCount + files.length > limits.maxFilesPerShare) {
      const remaining = limits.maxFilesPerShare - currentFileCount;
      return {
        ok: false,
        message: `You selected ${files.length} file(s) but can only add ${remaining} more (limit: ${limits.maxFilesPerShare} per share).`
      };
    }
    let batchBytes = 0;
    for (const file of files) {
      if (limits.maxFileSizeBytes > 0 && file.size > limits.maxFileSizeBytes) {
        return {
          ok: false,
          message: `"${file.name}" is ${formatLimitBytes(file.size)} which exceeds the per-file limit of ${formatLimitBytes(limits.maxFileSizeBytes)}.`
        };
      }
      batchBytes += file.size;
      if (limits.maxTotalUploadBytes > 0 && currentTotalBytes + batchBytes > limits.maxTotalUploadBytes) {
        return {
          ok: false,
          message: `Adding these files would exceed the total upload limit of ${formatLimitBytes(limits.maxTotalUploadBytes)}.`
        };
      }
    }
    return { ok: true };
  };
  var limitDialog = null;
  var limitDialogMessage = null;
  var ensureDialog = () => {
    if (limitDialog && limitDialogMessage) return { dialog: limitDialog, messageNode: limitDialogMessage };
    const dialog = document.createElement("dialog");
    dialog.className = "rounded-xl border border-border bg-white p-0 w-full max-w-sm m-auto";
    dialog.style.cssText = "margin: auto;";
    dialog.setAttribute("style", "margin: auto; --tw-shadow: 0 10px 15px -3px rgb(0 0 0 / .1); box-shadow: var(--tw-shadow);");
    const inner = document.createElement("div");
    inner.className = "p-5";
    const heading = document.createElement("h3");
    heading.className = "font-display text-2xl tracking-tight";
    heading.textContent = "Upload limit reached";
    const message = document.createElement("p");
    message.className = "text-sm text-ink-muted mt-2";
    const footer = document.createElement("div");
    footer.className = "mt-5 flex justify-end";
    const okButton = document.createElement("button");
    okButton.type = "button";
    okButton.className = "px-4 py-2 text-sm bg-terra text-white rounded-lg hover:bg-terra/90 transition-colors";
    okButton.textContent = "OK";
    okButton.addEventListener("click", () => dialog.close());
    footer.appendChild(okButton);
    inner.append(heading, message, footer);
    dialog.appendChild(inner);
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
    document.body.appendChild(dialog);
    limitDialog = dialog;
    limitDialogMessage = message;
    return { dialog, messageNode: message };
  };
  var showLimitDialog = (message) => {
    const { dialog, messageNode } = ensureDialog();
    messageNode.textContent = message;
    dialog.showModal();
  };
  var readLimitsFromElement = (el) => ({
    maxFilesPerShare: Number(el.dataset.maxFilesPerShare || "0"),
    maxFileSizeBytes: Number(el.dataset.maxFileSizeBytes || "0"),
    maxTotalUploadBytes: Number(el.dataset.maxTotalUploadBytes || "0")
  });

  // scripts/ts/public-upload.ts
  (() => {
    const form = document.querySelector("[data-public-upload-form]");
    if (!form) return;
    const fileInput = form.querySelector("[data-public-file-input]");
    const pickButton = form.querySelector("[data-public-pick-files]");
    const dropzone = form.querySelector("[data-public-dropzone]");
    const status = form.querySelector("[data-public-upload-status]");
    const uploadList = form.querySelector("[data-public-upload-list]");
    const hidden = form.querySelector("[data-public-upload-hidden]");
    const submit = form.querySelector("[data-public-submit]");
    const senderNameInput = form.querySelector('input[name="senderName"]');
    const senderEmailInput = form.querySelector('input[name="senderEmail"]');
    const uploadToken = form.querySelector("[data-public-upload-token]")?.value ?? "";
    const draftShareId = form.querySelector("[data-public-draft-share-id]")?.value ?? "";
    if (!fileInput || !pickButton || !dropzone || !status || !uploadList || !hidden || !submit || !uploadToken || !draftShareId) {
      return;
    }
    const limits = readLimitsFromElement(form);
    const senderNameStorageKey = "agora:public-upload:sender-name";
    const senderEmailStorageKey = "agora:public-upload:sender-email";
    const uploadedIds = /* @__PURE__ */ new Set();
    const uploadedSizes = /* @__PURE__ */ new Map();
    let activeUploads = 0;
    const pickPrimaryClass = "px-4 py-2 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors";
    const pickSecondaryClass = "px-4 py-2 bg-cream text-ink text-sm font-medium rounded-lg border border-border hover:bg-cream-dark/70 transition-colors";
    const formatBytes = (bytes) => {
      if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
      if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      return `${bytes} B`;
    };
    const refreshState = () => {
      const hasUploadedFiles = uploadedIds.size > 0;
      const senderEmail = (senderEmailInput?.value || "").trim();
      pickButton.className = hasUploadedFiles ? pickSecondaryClass : pickPrimaryClass;
      pickButton.textContent = hasUploadedFiles ? "Add more files" : "Select files";
      submit.classList.toggle("hidden", !hasUploadedFiles);
      let reason = "";
      if (activeUploads > 0) {
        reason = "Please wait for uploads to finish.";
      } else if (uploadedIds.size === 0) {
        reason = "Upload at least one file first.";
      } else if (!senderEmail) {
        reason = "Enter your email first.";
      }
      submit.disabled = reason.length > 0;
      submit.title = reason;
      if (activeUploads > 0) {
        status.textContent = `Uploading ${activeUploads} file(s)...`;
        return;
      }
      status.textContent = uploadedIds.size > 0 ? `${uploadedIds.size} file(s) uploaded and ready.` : "No files uploaded yet.";
    };
    const restoreSenderFields = () => {
      if (!senderNameInput && !senderEmailInput) return;
      try {
        if (senderNameInput && !senderNameInput.value) {
          senderNameInput.value = (localStorage.getItem(senderNameStorageKey) || "").trim();
        }
        if (senderEmailInput && !senderEmailInput.value) {
          senderEmailInput.value = (localStorage.getItem(senderEmailStorageKey) || "").trim();
        }
      } catch {
      }
    };
    const persistSenderFields = () => {
      if (!senderNameInput && !senderEmailInput) return;
      try {
        if (senderNameInput) {
          localStorage.setItem(senderNameStorageKey, senderNameInput.value.trim());
        }
        if (senderEmailInput) {
          localStorage.setItem(senderEmailStorageKey, senderEmailInput.value.trim());
        }
      } catch {
      }
    };
    const createRow = (file) => {
      const row = document.createElement("li");
      row.className = "rounded-lg border border-border bg-white px-2.5 py-2 min-w-0";
      const name = document.createElement("p");
      name.className = "text-xs text-ink-light truncate";
      name.textContent = file.name;
      const barWrap = document.createElement("div");
      barWrap.className = "mt-1.5 h-1 bg-cream-dark rounded-full overflow-hidden";
      const bar = document.createElement("div");
      bar.className = "h-full bg-terra transition-all";
      bar.style.width = "0%";
      barWrap.appendChild(bar);
      const note = document.createElement("p");
      note.className = "text-[11px] text-ink-muted mt-1";
      note.textContent = "Pending";
      row.append(name, barWrap, note);
      uploadList.appendChild(row);
      return { row, bar, note };
    };
    const addHidden = (id) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "uploadedFileIds";
      input.value = id;
      input.setAttribute("data-uploaded-file-id", id);
      hidden.appendChild(input);
    };
    const uploadSingleFile = (file) => {
      const ui = createRow(file);
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/public-uploads/stage");
        xhr.responseType = "json";
        xhr.upload.addEventListener("progress", (event) => {
          if (!event.lengthComputable) return;
          const percent = Math.min(100, Math.round(event.loaded / event.total * 100));
          ui.bar.style.width = `${percent}%`;
          ui.note.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
        });
        xhr.addEventListener("load", () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            const payload2 = xhr.response;
            if (!payload2?.uploadId) {
              reject(new Error("Upload failed."));
              return;
            }
            uploadedIds.add(payload2.uploadId);
            uploadedSizes.set(payload2.uploadId, file.size);
            addHidden(payload2.uploadId);
            ui.row.className = "rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-2 min-w-0";
            ui.note.className = "text-[11px] text-sage mt-1";
            ui.note.textContent = `Uploaded \xB7 ${formatBytes(file.size)}`;
            resolve();
            return;
          }
          const payload = xhr.response;
          reject(new Error(payload?.error?.trim() || "Upload failed."));
        });
        xhr.addEventListener("error", () => reject(new Error("Upload failed.")));
        const formData = new FormData();
        formData.append("uploadToken", uploadToken);
        formData.append("draftShareId", draftShareId);
        formData.append("file", file, file.name);
        xhr.send(formData);
      });
    };
    const queueUploads = async (files) => {
      const selected = Array.from(files ?? []);
      if (selected.length === 0 || activeUploads > 0) {
        return;
      }
      const currentTotalBytes = Array.from(uploadedSizes.values()).reduce((sum, size) => sum + size, 0);
      const result = validateFileSelection(selected, limits, uploadedIds.size, currentTotalBytes);
      if (!result.ok) {
        showLimitDialog(result.message);
        return;
      }
      for (const file of selected) {
        activeUploads += 1;
        refreshState();
        try {
          await uploadSingleFile(file);
        } catch (error) {
          status.textContent = error instanceof Error ? error.message : "Upload failed.";
        } finally {
          activeUploads -= 1;
          refreshState();
        }
      }
    };
    pickButton.addEventListener("click", () => {
      if (activeUploads > 0) return;
      fileInput.click();
    });
    dropzone.addEventListener("click", () => {
      if (activeUploads > 0) return;
      fileInput.click();
    });
    fileInput.addEventListener("change", () => {
      void queueUploads(fileInput.files);
      fileInput.value = "";
    });
    dropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropzone.classList.add("ring-2", "ring-terra/40");
    });
    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("ring-2", "ring-terra/40");
    });
    dropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropzone.classList.remove("ring-2", "ring-terra/40");
      void queueUploads(event.dataTransfer?.files || []);
    });
    restoreSenderFields();
    senderNameInput?.addEventListener("input", persistSenderFields);
    senderEmailInput?.addEventListener("input", persistSenderFields);
    senderEmailInput?.addEventListener("input", refreshState);
    refreshState();
  })();
})();
//# sourceMappingURL=public-upload.js.map
