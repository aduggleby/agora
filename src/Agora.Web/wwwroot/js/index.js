"use strict";
(() => {
  // Scripts/index.ts
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
    const draftIdInput = document.querySelector("[data-quick-share-draft-id]");
    if (!dropzone || !fileInput || !pickButton || !status || !draftIdInput?.value) return;
    const draftShareId = draftIdInput.value;
    const setStatus = (text, isError) => {
      status.textContent = text;
      status.classList.remove("text-ink-muted", "text-danger");
      status.classList.add(isError ? "text-danger" : "text-ink-muted");
    };
    const uploadSingleFile = async (file) => {
      const formData = new FormData();
      formData.append("draftShareId", draftShareId);
      formData.append("file", file, file.name);
      const response = await fetch("/api/uploads/stage", { method: "POST", body: formData });
      if (!response.ok) {
        let error = "Upload failed.";
        try {
          const json = await response.json();
          if (json.error) {
            error = json.error;
          }
        } catch {
        }
        throw new Error(error);
      }
    };
    const queueAndUpload = async (files) => {
      const list = Array.from(files ?? []);
      if (list.length === 0) return;
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
