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

  // scripts/ts/shares-new.ts
  (() => {
    const form = document.querySelector("[data-share-form]");
    if (!form) return;
    const fileInput = form.querySelector("[data-file-input]");
    const pickButton = form.querySelector("[data-pick-files]");
    const cancelUploadsButton = form.querySelector("[data-upload-cancel]");
    const list = form.querySelector("[data-upload-list]");
    const hidden = form.querySelector("[data-upload-hidden]");
    const status = form.querySelector("[data-upload-status]");
    const submit = form.querySelector("[data-submit]");
    const submitPending = form.querySelector("[data-submit-pending]");
    const dropzone = form.querySelector("[data-dropzone]");
    const expiryModeInput = form.querySelector('[name="expiryMode"]');
    const expiresAtInput = form.querySelector('[name="expiresAtUtc"]');
    const accountDefaultExpiryInput = form.querySelector("[data-account-default-expiry-mode]");
    const optionsToggle = form.querySelector("[data-options-toggle]");
    const optionsHeader = form.querySelector("[data-options-header]");
    const optionsToggleLabel = form.querySelector("[data-options-toggle-label]");
    const optionsToggleIcon = form.querySelector("[data-options-icon]");
    const optionsPanel = form.querySelector("[data-options-panel]");
    const shareTokenInput = form.querySelector("[data-share-token]");
    const downloadPasswordInput = form.querySelector('[name="downloadPassword"]');
    const suggestedShareTokenButton = form.querySelector("[data-suggested-share-token]");
    const draftShareIdInput = form.querySelector("[data-draft-share-id]");
    const removeDialog = form.querySelector("[data-upload-remove-dialog]");
    const removeNameNode = form.querySelector("[data-upload-remove-file-name]");
    const removeCancelButton = form.querySelector("[data-upload-remove-cancel]");
    const removeConfirmButton = form.querySelector("[data-upload-remove-confirm]");
    if (!fileInput || !pickButton || !cancelUploadsButton || !list || !hidden || !status || !submit || !draftShareIdInput) return;
    const limits = readLimitsFromElement(form);
    const uploadedIds = /* @__PURE__ */ new Set();
    hidden.querySelectorAll('input[name="uploadedFileIds"]').forEach((input) => {
      if (input.value) uploadedIds.add(input.value);
    });
    let activeUploads = 0;
    let manualExpiryValue = "";
    let pendingRemoval = null;
    let isSubmitting = false;
    let cancelRequested = false;
    const activeRequests = /* @__PURE__ */ new Set();
    const optionsStorageKey = "agora:new-share:options-collapsed";
    const pickPrimaryClass = "px-4 py-2 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors";
    const pickSecondaryClass = "px-4 py-2 bg-cream text-ink text-sm font-medium rounded-lg border border-border hover:bg-cream-dark/70 transition-colors";
    const setOptionsCollapsed = (isCollapsed) => {
      if (!optionsPanel || !optionsToggle) return;
      optionsPanel.classList.toggle("hidden", isCollapsed);
      if (optionsToggleLabel) optionsToggleLabel.textContent = isCollapsed ? "Show options" : "Hide options";
      if (optionsToggleIcon) optionsToggleIcon.classList.toggle("rotate-180", !isCollapsed);
      optionsToggle.setAttribute("aria-expanded", String(!isCollapsed));
      optionsHeader?.setAttribute("aria-expanded", String(!isCollapsed));
    };
    const toggleOptions = () => {
      if (!optionsPanel) return;
      const nextCollapsed = !optionsPanel.classList.contains("hidden");
      setOptionsCollapsed(nextCollapsed);
      try {
        localStorage.setItem(optionsStorageKey, nextCollapsed ? "collapsed" : "expanded");
      } catch {
      }
    };
    const toLocalDateTimeValue = (date) => {
      const pad = (n) => String(n).padStart(2, "0");
      return [
        date.getFullYear(),
        "-",
        pad(date.getMonth() + 1),
        "-",
        pad(date.getDate()),
        "T",
        pad(date.getHours()),
        ":",
        pad(date.getMinutes())
      ].join("");
    };
    const formatBytes = (bytes) => {
      if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
      if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      return `${bytes} B`;
    };
    const resolveEffectiveExpiryMode = () => {
      const selected = (expiryModeInput?.value || "account_default").trim().toLowerCase();
      if (selected !== "account_default") return selected;
      return (accountDefaultExpiryInput?.value || "7_days").trim().toLowerCase();
    };
    const computeExpiryDate = (mode, now) => {
      switch (mode) {
        case "1_hour":
          return new Date(now.getTime() + 1 * 60 * 60 * 1e3);
        case "24_hours":
          return new Date(now.getTime() + 24 * 60 * 60 * 1e3);
        case "7_days":
          return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1e3);
        case "30_days":
          return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1e3);
        case "1_year": {
          const d = new Date(now.getTime());
          d.setFullYear(d.getFullYear() + 1);
          return d;
        }
        default:
          return null;
      }
    };
    const syncExpiryInput = () => {
      if (!expiresAtInput) return;
      const effectiveMode = resolveEffectiveExpiryMode();
      const now = /* @__PURE__ */ new Date();
      const isManualDate = effectiveMode === "date";
      if (isManualDate) {
        expiresAtInput.disabled = false;
        const parsed = expiresAtInput.value ? new Date(expiresAtInput.value) : null;
        if (parsed && !Number.isNaN(parsed.getTime()) && parsed.getTime() > now.getTime()) {
          manualExpiryValue = expiresAtInput.value;
        }
        if (!manualExpiryValue) {
          manualExpiryValue = toLocalDateTimeValue(new Date(now.getTime() + 24 * 60 * 60 * 1e3));
        }
        expiresAtInput.value = manualExpiryValue;
        expiresAtInput.title = "";
        return;
      }
      if (!expiresAtInput.disabled && expiresAtInput.value) {
        manualExpiryValue = expiresAtInput.value;
      }
      expiresAtInput.disabled = true;
      const calculated = computeExpiryDate(effectiveMode, now);
      if (!calculated) {
        expiresAtInput.value = "";
        expiresAtInput.title = effectiveMode === "indefinite" ? "No expiry date for indefinite mode." : "Calculated from expiry mode.";
        return;
      }
      expiresAtInput.value = toLocalDateTimeValue(calculated);
      expiresAtInput.title = "Calculated from expiry mode.";
    };
    const refreshState = () => {
      if (isSubmitting) {
        submit.disabled = true;
        submit.title = "Preparing your link...";
        return;
      }
      const hasUploadedFiles = uploadedIds.size > 0;
      pickButton.className = hasUploadedFiles ? pickSecondaryClass : pickPrimaryClass;
      pickButton.textContent = hasUploadedFiles ? "Add more files" : "Select files";
      syncExpiryInput();
      const effectiveExpiryMode = resolveEffectiveExpiryMode();
      let reason = "";
      if (activeUploads > 0) reason = "Please wait for uploads to finish.";
      else if (uploadedIds.size === 0) reason = "Upload at least one file first.";
      else if (shareTokenInput) {
        const token = (shareTokenInput.value || "").trim();
        if (token.length < 3 || token.length > 64 || !/^[A-Za-z0-9_-]+$/.test(token)) {
          reason = "Share link must be 3-64 letters, numbers, hyphens, or underscores.";
        }
      }
      if (!reason && downloadPasswordInput) {
        const value = (downloadPasswordInput.value || "").trim();
        if (value.length > 0 && value.length < 8) {
          reason = "Download password must be at least 8 characters.";
        }
      }
      if (!reason && effectiveExpiryMode === "date") {
        if (!expiresAtInput?.value) reason = "Pick an expiry date and time.";
        else {
          const value = new Date(expiresAtInput.value).getTime();
          if (Number.isNaN(value) || value <= Date.now()) {
            reason = "Expiry date must be in the future.";
          }
        }
      }
      submit.disabled = reason.length > 0;
      submit.title = reason;
      if (activeUploads > 0) {
        status.textContent = `Uploading ${activeUploads} file(s)...`;
        cancelUploadsButton.classList.remove("hidden");
        cancelUploadsButton.disabled = false;
        cancelUploadsButton.title = "Cancel upload and queue immediate cleanup.";
        return;
      }
      cancelUploadsButton.classList.add("hidden");
      cancelUploadsButton.disabled = true;
      cancelUploadsButton.title = "No upload is currently running.";
      status.textContent = uploadedIds.size > 0 ? `${uploadedIds.size} file(s) uploaded and ready.` : "No files uploaded yet.";
    };
    const markCanceledUi = (ui, detail) => {
      ui.row.className = "relative rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0";
      ui.barWrap.style.display = "none";
      ui.state.textContent = detail || "Canceled";
      ui.state.className = "text-[11px] text-ink-muted mt-1";
      ui.remove.classList.add("hidden");
    };
    const queueDraftCleanup = async () => {
      const data = new FormData();
      data.append("draftShareId", draftShareIdInput.value);
      try {
        const response = await fetch("/api/uploads/cancel", { method: "POST", body: data, credentials: "same-origin" });
        if (!response.ok) throw new Error();
        status.textContent = "Upload canceled. Cleanup queued in background.";
      } catch {
        status.textContent = "Upload canceled. Cleanup request failed; please retry.";
      }
    };
    const addHidden = (id) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "uploadedFileIds";
      input.value = id;
      input.setAttribute("data-uploaded-file-id", id);
      hidden.appendChild(input);
    };
    const removeHidden = (id) => {
      hidden.querySelectorAll('input[name="uploadedFileIds"]').forEach((input) => {
        if (input.value === id) input.remove();
      });
    };
    const executeRemove = (id, row) => {
      if (!id) return;
      const data = new FormData();
      data.append("uploadId", id);
      data.append("draftShareId", draftShareIdInput.value);
      fetch("/api/uploads/remove", { method: "POST", body: data }).then((response) => {
        if (!response.ok) throw new Error();
        uploadedIds.delete(id);
        removeHidden(id);
        row?.remove();
        refreshState();
      }).catch(() => {
        status.textContent = "Unable to remove file right now.";
      });
    };
    const requestRemove = (id, row) => {
      if (!id) return;
      pendingRemoval = { id, row };
      if (removeNameNode) {
        const fileNameNode = row?.querySelector("p");
        removeNameNode.textContent = (fileNameNode?.textContent || "").trim() || "this file";
      }
      if (removeDialog && typeof removeDialog.showModal === "function") {
        removeDialog.showModal();
        return;
      }
      executeRemove(id, row);
    };
    const createRow = (file) => {
      const row = document.createElement("li");
      row.className = "relative rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0";
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "absolute right-1 top-1 p-0.5 text-ink-muted hover:text-danger leading-none text-sm font-semibold hidden";
      remove.textContent = "x";
      remove.title = "Remove file";
      const name = document.createElement("p");
      name.className = "text-xs text-ink-light truncate pr-6";
      name.textContent = file.name;
      const size = document.createElement("p");
      size.className = "text-[11px] text-ink-muted mt-0.5";
      size.textContent = formatBytes(file.size);
      const barWrap = document.createElement("div");
      barWrap.className = "mt-1.5 h-1 bg-white rounded-full overflow-hidden";
      const bar = document.createElement("div");
      bar.className = "h-full bg-terra transition-all";
      bar.style.width = "0%";
      barWrap.appendChild(bar);
      const state = document.createElement("p");
      state.className = "text-[11px] text-ink-muted mt-1";
      state.textContent = "Pending";
      row.append(remove, name, size, barWrap, state);
      list.appendChild(row);
      return { row, remove, size, barWrap, bar, state };
    };
    const resolveUploadErrorMessage = (xhr) => {
      if (xhr.status === 413) {
        return "Upload failed: file is larger than the server request limit.";
      }
      const payload = xhr.response;
      if (payload && typeof payload.error === "string" && payload.error.trim()) {
        return payload.error.trim();
      }
      const text = (xhr.responseText || "").trim();
      if (text.length > 0) {
        try {
          const parsed = JSON.parse(text);
          if (parsed?.error?.trim()) {
            return parsed.error.trim();
          }
        } catch {
          return text.length <= 180 ? text : `${text.slice(0, 180)}...`;
        }
      }
      return "Upload failed.";
    };
    const uploadFile = (file) => {
      const ui = createRow(file);
      activeUploads += 1;
      refreshState();
      const xhr = new XMLHttpRequest();
      activeRequests.add(xhr);
      xhr.open("POST", "/api/uploads/stage");
      xhr.responseType = "json";
      let settled = false;
      const finalize = () => {
        if (settled) return;
        settled = true;
        activeRequests.delete(xhr);
        activeUploads = Math.max(0, activeUploads - 1);
        refreshState();
      };
      xhr.upload.addEventListener("progress", (event) => {
        if (!event.lengthComputable) return;
        const percent = Math.min(100, Math.round(event.loaded / event.total * 100));
        ui.bar.style.width = `${percent}%`;
        ui.state.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
      });
      xhr.addEventListener("load", () => {
        finalize();
        const response = xhr.response;
        if (cancelRequested) {
          markCanceledUi(ui, "Canceled (cleanup queued)");
          return;
        }
        if (xhr.status >= 200 && xhr.status < 300 && response?.uploadId) {
          const id = response.uploadId;
          uploadedIds.add(id);
          addHidden(id);
          ui.row.setAttribute("data-upload-id", id);
          ui.row.setAttribute("data-upload-size-bytes", String(file.size || 0));
          ui.row.className = "relative rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-1.5 min-w-0";
          ui.size.style.display = "none";
          ui.barWrap.style.display = "none";
          ui.state.textContent = formatBytes(file.size);
          ui.state.className = "text-[11px] text-sage mt-0.5";
          ui.remove.classList.remove("hidden");
          ui.remove.addEventListener("click", () => requestRemove(id, ui.row));
        } else {
          const errorMessage = resolveUploadErrorMessage(xhr);
          ui.row.className = "relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0";
          ui.bar.className = "h-full bg-danger";
          ui.state.textContent = errorMessage;
          ui.state.className = "text-[11px] text-danger mt-1";
          status.textContent = errorMessage;
        }
      });
      xhr.addEventListener("abort", () => {
        finalize();
        markCanceledUi(ui);
      });
      xhr.addEventListener("error", () => {
        finalize();
        if (cancelRequested) {
          markCanceledUi(ui);
          return;
        }
        const errorMessage = resolveUploadErrorMessage(xhr);
        ui.row.className = "relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0";
        ui.bar.className = "h-full bg-danger";
        ui.state.textContent = errorMessage;
        ui.state.className = "text-[11px] text-danger mt-1";
        status.textContent = errorMessage;
      });
      const data = new FormData();
      data.append("draftShareId", draftShareIdInput.value);
      data.append("file", file, file.name);
      xhr.send(data);
    };
    cancelUploadsButton.addEventListener("click", async () => {
      if (activeUploads <= 0 || cancelRequested) return;
      cancelRequested = true;
      cancelUploadsButton.disabled = true;
      cancelUploadsButton.title = "Canceling upload...";
      status.textContent = "Canceling upload...";
      uploadedIds.clear();
      hidden.querySelectorAll('input[name="uploadedFileIds"]').forEach((input) => input.remove());
      activeRequests.forEach((request) => request.abort());
      await queueDraftCleanup();
      cancelRequested = false;
      refreshState();
    });
    list.querySelectorAll("[data-upload-remove]").forEach((button) => {
      button.addEventListener("click", () => {
        const row = button.closest("[data-upload-id]");
        const id = row?.getAttribute("data-upload-id") || "";
        if (!id) return;
        requestRemove(id, row);
      });
    });
    removeCancelButton?.addEventListener("click", () => {
      pendingRemoval = null;
      removeDialog?.close();
    });
    removeConfirmButton?.addEventListener("click", () => {
      if (pendingRemoval) {
        executeRemove(pendingRemoval.id, pendingRemoval.row);
      }
      pendingRemoval = null;
      removeDialog?.close();
    });
    const queueSelectedFiles = (files) => {
      const selected = Array.from(files ?? []);
      if (selected.length === 0) return;
      cancelRequested = false;
      const currentFileCount = uploadedIds.size + activeUploads;
      const currentTotalBytes = Array.from(list.querySelectorAll("[data-upload-size-bytes]")).map((row) => Number(row.getAttribute("data-upload-size-bytes") || "0")).filter((value) => Number.isFinite(value) && value > 0).reduce((sum, value) => sum + value, 0);
      const result = validateFileSelection(selected, limits, currentFileCount, currentTotalBytes);
      if (!result.ok) {
        showLimitDialog(result.message);
        return;
      }
      selected.forEach((file) => uploadFile(file));
    };
    pickButton.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
      queueSelectedFiles(fileInput.files || []);
      fileInput.value = "";
    });
    dropzone?.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropzone.classList.add("ring-2", "ring-terra/40");
    });
    dropzone?.addEventListener("dragleave", () => dropzone.classList.remove("ring-2", "ring-terra/40"));
    dropzone?.addEventListener("drop", (event) => {
      event.preventDefault();
      dropzone.classList.remove("ring-2", "ring-terra/40");
      queueSelectedFiles(event.dataTransfer?.files || []);
    });
    expiryModeInput?.addEventListener("change", refreshState);
    expiresAtInput?.addEventListener("input", refreshState);
    shareTokenInput?.addEventListener("input", refreshState);
    downloadPasswordInput?.addEventListener("input", refreshState);
    suggestedShareTokenButton?.addEventListener("click", () => {
      if (!shareTokenInput) return;
      shareTokenInput.value = suggestedShareTokenButton.getAttribute("data-suggested-share-token") || shareTokenInput.value;
      shareTokenInput.focus();
      shareTokenInput.select();
      refreshState();
    });
    if (optionsPanel && optionsToggle) {
      let isCollapsed = true;
      try {
        const saved = localStorage.getItem(optionsStorageKey);
        if (saved === "expanded") isCollapsed = false;
        else if (saved === "collapsed") isCollapsed = true;
      } catch {
      }
      setOptionsCollapsed(isCollapsed);
      optionsToggle.addEventListener("click", (event) => {
        event.stopPropagation();
        toggleOptions();
      });
      optionsHeader?.addEventListener("click", (event) => {
        if (event.target?.closest("[data-options-toggle]")) return;
        toggleOptions();
      });
      optionsHeader?.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        toggleOptions();
      });
    }
    form.addEventListener("submit", (event) => {
      if (submit.disabled || isSubmitting) {
        event.preventDefault();
        return;
      }
      isSubmitting = true;
      submit.disabled = true;
      submit.title = "Preparing your link...";
      submit.textContent = "Preparing your link...";
      submitPending?.classList.remove("hidden");
      form.setAttribute("aria-busy", "true");
      fileInput.disabled = true;
      pickButton.disabled = true;
      optionsToggle?.setAttribute("disabled", "disabled");
      shareTokenInput?.setAttribute("readonly", "readonly");
      downloadPasswordInput?.setAttribute("readonly", "readonly");
      refreshState();
    });
    const modeInput = form.querySelector("[data-template-mode]");
    const summary = form.querySelector("[data-template-summary]");
    const titleInput = form.querySelector("[data-template-title]");
    const h1Input = form.querySelector("[data-template-h1]");
    const customActions = form.querySelector("[data-template-custom-actions]");
    const designerLink = form.querySelector("[data-template-designer-link]");
    const refreshTemplateMode = () => {
      if (!modeInput) return;
      if (modeInput.value !== "per_upload") {
        if (summary) summary.textContent = "Using account default template.";
        customActions?.classList.add("hidden");
        return;
      }
      if (summary) {
        summary.textContent = `Custom design selected: ${h1Input?.value || titleInput?.value || "Untitled"}.`;
      }
      customActions?.classList.remove("hidden");
    };
    designerLink?.addEventListener("click", (event) => {
      if (modeInput?.value !== "per_upload") event.preventDefault();
    });
    modeInput?.addEventListener("change", refreshTemplateMode);
    refreshTemplateMode();
    refreshState();
  })();
})();
//# sourceMappingURL=shares-new.js.map
