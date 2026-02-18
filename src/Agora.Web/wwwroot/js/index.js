"use strict";
(() => {
  // scripts/ts/index.ts
  (() => {
    const nodes = document.querySelectorAll("[data-local-datetime]");
    const formatter = new Intl.DateTimeFormat(void 0, { dateStyle: "medium", timeStyle: "short" });
    nodes.forEach((node) => {
      const value = node.getAttribute("data-local-datetime");
      if (!value) return;
      const date = new Date(value);
      if (!Number.isNaN(date.getTime())) {
        node.textContent = formatter.format(date);
      }
    });
  })();
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
          nameNode.textContent = form.getAttribute("data-share-name") ?? "";
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
  (() => {
    const dialog = document.querySelector("[data-share-details-dialog]");
    if (!dialog) return;
    const nameNode = dialog.querySelector("[data-share-details-name]");
    const listNode = dialog.querySelector("[data-share-details-list]");
    const closeButton = dialog.querySelector("[data-share-details-close]");
    if (!listNode) return;
    const formatBytes = (bytes) => {
      const value = Number(bytes || 0);
      if (!Number.isFinite(value) || value <= 0) return "0 B";
      if (value >= 1024 * 1024 * 1024) return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
      if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
      if (value >= 1024) return `${Math.round(value / 1024)} KB`;
      return `${Math.round(value)} B`;
    };
    const getText = (item, key) => {
      const alt = key.charAt(0).toUpperCase() + key.slice(1);
      const value = item[key] ?? item[alt];
      return typeof value === "string" ? value : "";
    };
    const getNumber = (item, key) => {
      const alt = key.charAt(0).toUpperCase() + key.slice(1);
      const value = item[key] ?? item[alt] ?? 0;
      const numeric = Number(value);
      return Number.isFinite(numeric) ? numeric : 0;
    };
    document.querySelectorAll("[data-share-details-trigger]").forEach((button) => {
      button.addEventListener("click", () => {
        const shareName = button.getAttribute("data-share-name") ?? "";
        const raw = button.getAttribute("data-share-files") ?? "[]";
        let files = [];
        try {
          const parsed = JSON.parse(raw);
          files = Array.isArray(parsed) ? parsed : [];
        } catch {
          files = [];
        }
        files.sort(
          (a, b) => getText(a, "originalFilename").localeCompare(getText(b, "originalFilename"), void 0, {
            sensitivity: "base"
          })
        );
        listNode.innerHTML = "";
        files.forEach((file) => {
          const fileName = getText(file, "originalFilename");
          const fileSize = getNumber(file, "originalSizeBytes");
          const row = document.createElement("tr");
          row.className = "border-b border-border/60 last:border-b-0";
          const nameCell = document.createElement("td");
          nameCell.className = "px-3 py-2 text-sm text-ink-light";
          nameCell.textContent = fileName;
          const sizeCell = document.createElement("td");
          sizeCell.className = "px-3 py-2 text-sm text-ink-muted text-right";
          sizeCell.textContent = formatBytes(fileSize);
          row.append(nameCell, sizeCell);
          listNode.appendChild(row);
        });
        if (files.length === 0) {
          const row = document.createElement("tr");
          row.innerHTML = '<td colspan="2" class="px-3 py-3 text-sm text-ink-muted">No file metadata available.</td>';
          listNode.appendChild(row);
        }
        if (nameNode) {
          nameNode.textContent = shareName;
        }
        dialog.showModal();
      });
    });
    closeButton?.addEventListener("click", () => dialog.close());
  })();
  (() => {
    const dropzone = document.querySelector("[data-quick-share-dropzone]");
    const fileInput = document.querySelector("[data-quick-share-input]");
    const pickButton = document.querySelector("[data-quick-share-pick]");
    const status = document.querySelector("[data-quick-share-status]");
    const uploadList = document.querySelector("[data-quick-share-upload-list]");
    const draftIdInput = document.querySelector("[data-quick-share-draft-id]");
    if (!dropzone || !fileInput || !pickButton || !status || !uploadList || !draftIdInput?.value) return;
    const draftShareId = draftIdInput.value;
    const setStatus = (text, isError) => {
      status.textContent = text;
      status.classList.remove("text-ink-muted", "text-danger");
      status.classList.add(isError ? "text-danger" : "text-ink-muted");
    };
    const formatBytes = (bytes) => {
      if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
      if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      return `${bytes} B`;
    };
    const createUploadRow = (file) => {
      const row = document.createElement("li");
      row.className = "rounded-lg border border-border bg-white px-2.5 py-2 min-w-0";
      const name = document.createElement("p");
      name.className = "text-xs text-ink-light truncate";
      name.textContent = file.name;
      const size = document.createElement("p");
      size.className = "text-[11px] text-ink-muted mt-0.5";
      size.textContent = formatBytes(file.size);
      const barWrap = document.createElement("div");
      barWrap.className = "mt-1.5 h-1 bg-cream-dark rounded-full overflow-hidden";
      const bar = document.createElement("div");
      bar.className = "h-full bg-terra transition-all";
      bar.style.width = "0%";
      barWrap.appendChild(bar);
      const state = document.createElement("p");
      state.className = "text-[11px] text-ink-muted mt-1";
      state.textContent = "Queued...";
      row.append(name, size, barWrap, state);
      uploadList.appendChild(row);
      return { row, size, bar, state };
    };
    const uploadSingleFile = (file) => {
      const ui = createUploadRow(file);
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/uploads/stage");
        xhr.responseType = "json";
        xhr.upload.addEventListener("progress", (event) => {
          if (!event.lengthComputable) return;
          const percent = Math.min(100, Math.round(event.loaded / event.total * 100));
          ui.bar.style.width = `${percent}%`;
          ui.state.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
        });
        xhr.addEventListener("load", () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            ui.row.className = "rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-2 min-w-0";
            ui.size.style.display = "none";
            ui.state.textContent = formatBytes(file.size);
            ui.state.className = "text-[11px] text-sage mt-1";
            resolve();
            return;
          }
          const payload = xhr.response;
          const message = payload?.error?.trim() || "Upload failed.";
          ui.row.className = "rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0";
          ui.state.textContent = message;
          ui.state.className = "text-[11px] text-danger mt-1";
          reject(new Error(message));
        });
        xhr.addEventListener("error", () => {
          ui.row.className = "rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0";
          ui.state.textContent = "Upload failed.";
          ui.state.className = "text-[11px] text-danger mt-1";
          reject(new Error("Upload failed."));
        });
        const formData = new FormData();
        formData.append("draftShareId", draftShareId);
        formData.append("file", file, file.name);
        xhr.send(formData);
      });
    };
    const queueAndUpload = async (files) => {
      const list = Array.from(files ?? []);
      if (list.length === 0) return;
      uploadList.innerHTML = "";
      setStatus(`Uploading ${list.length} file(s)...`, false);
      try {
        for (const file of list) {
          await uploadSingleFile(file);
        }
        setStatus("Upload complete. Redirecting to share setup...", false);
        window.location.href = `/shares/new?draftShareId=${encodeURIComponent(draftShareId)}`;
      } catch (error) {
        const message = error instanceof Error ? error.message : "Upload failed.";
        setStatus(message, true);
      }
    };
    pickButton.addEventListener("click", (event) => {
      event.stopPropagation();
      fileInput.click();
    });
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      fileInput.click();
    });
    fileInput.addEventListener("change", () => {
      queueAndUpload(fileInput.files);
      fileInput.value = "";
    });
    dropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropzone.classList.add("ring-2", "ring-terra/40");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("ring-2", "ring-terra/40"));
    dropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropzone.classList.remove("ring-2", "ring-terra/40");
      queueAndUpload(event.dataTransfer?.files ?? []);
    });
  })();
})();
//# sourceMappingURL=index.js.map
