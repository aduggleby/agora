"use strict";
(() => {
  // scripts/ts/quick-share-dropzone.ts
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
      if (response.ok) return;
      let error = "Upload failed.";
      try {
        const json = await response.json();
        if (json?.error) error = json.error;
      } catch {
      }
      throw new Error(error);
    };
    const queueAndUpload = async (files) => {
      const list = Array.from(files || []);
      if (!list.length) return;
      setStatus(`Uploading ${list.length} file(s)...`, false);
      try {
        for (const file of list) {
          await uploadSingleFile(file);
        }
        setStatus("Upload complete. Redirecting to share setup...", false);
        window.location.href = `/shares/new?draftShareId=${encodeURIComponent(draftShareId)}`;
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Upload failed.", true);
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
      queueAndUpload(event.dataTransfer?.files || []);
    });
  })();
})();
//# sourceMappingURL=quick-share-dropzone.js.map
