import { readLimitsFromElement, validateFileSelection, showLimitDialog } from './upload-limits';

(() => {
  const dropzone = document.querySelector<HTMLElement>('[data-quick-share-dropzone]');
  const fileInput = document.querySelector<HTMLInputElement>('[data-quick-share-input]');
  const pickButton = document.querySelector<HTMLButtonElement>('[data-quick-share-pick]');
  const cancelButton = document.querySelector<HTMLButtonElement>('[data-quick-share-cancel]');
  const status = document.querySelector<HTMLElement>('[data-quick-share-status]');
  const uploadList = document.querySelector<HTMLUListElement>('[data-quick-share-upload-list]');
  const draftIdInput = document.querySelector<HTMLInputElement>('[data-quick-share-draft-id]');
  if (!dropzone || !fileInput || !pickButton || !cancelButton || !status || !uploadList || !draftIdInput?.value) return;

  const limits = readLimitsFromElement(dropzone);

  const draftShareId = draftIdInput.value;
  let activeXhr: XMLHttpRequest | null = null;
  let isUploading = false;
  let cancelRequested = false;

  type UploadUi = {
    row: HTMLLIElement;
    size: HTMLParagraphElement;
    barWrap: HTMLDivElement;
    bar: HTMLDivElement;
    state: HTMLParagraphElement;
  };

  const setStatus = (text: string, isError: boolean): void => {
    status.textContent = text;
    status.classList.remove('text-ink-muted', 'text-danger');
    status.classList.add(isError ? 'text-danger' : 'text-ink-muted');
  };

  const formatBytes = (bytes: number): string => {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} B`;
  };

  const setControls = (uploading: boolean): void => {
    isUploading = uploading;
    fileInput.disabled = uploading;
    pickButton.disabled = uploading;
    pickButton.title = uploading ? 'Upload in progress.' : '';
    cancelButton.classList.toggle('hidden', !uploading);
    cancelButton.disabled = !uploading;
    cancelButton.title = uploading ? 'Cancel upload and queue immediate cleanup.' : 'No upload is currently running.';
  };

  const createUploadRow = (file: File): UploadUi => {
    const row = document.createElement('li');
    row.className = 'rounded-lg border border-border bg-white px-2.5 py-2 min-w-0';

    const name = document.createElement('p');
    name.className = 'text-xs text-ink-light truncate';
    name.textContent = file.name;

    const size = document.createElement('p');
    size.className = 'text-[11px] text-ink-muted mt-0.5';
    size.textContent = formatBytes(file.size);

    const barWrap = document.createElement('div');
    barWrap.className = 'mt-1.5 h-1 bg-cream-dark rounded-full overflow-hidden';

    const bar = document.createElement('div');
    bar.className = 'h-full bg-terra transition-all';
    bar.style.width = '0%';
    barWrap.appendChild(bar);

    const state = document.createElement('p');
    state.className = 'text-[11px] text-ink-muted mt-1';
    state.textContent = 'Pending';

    row.append(name, size, barWrap, state);
    uploadList.appendChild(row);
    return { row, size, barWrap, bar, state };
  };

  const markCanceledCard = (ui: UploadUi): void => {
    ui.row.className = 'rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0';
    ui.barWrap.style.display = 'none';
    ui.state.textContent = 'Canceled';
    ui.state.className = 'text-[11px] text-ink-muted mt-1';
  };

  const uploadSingleFile = (file: File, ui: UploadUi): Promise<string> => {
    return new Promise<string>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      activeXhr = xhr;
      xhr.open('POST', '/api/uploads/stage');
      xhr.responseType = 'json';

      xhr.upload.addEventListener('progress', (event) => {
        if (!event.lengthComputable) return;
        const percent = Math.min(100, Math.round((event.loaded / event.total) * 100));
        ui.bar.style.width = `${percent}%`;
        ui.state.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
      });

      xhr.addEventListener('load', () => {
        activeXhr = null;
        if (xhr.status >= 200 && xhr.status < 300) {
          const payload = xhr.response as { uploadId?: string } | null;
          if (!payload?.uploadId) {
            reject(new Error('Upload failed.'));
            return;
          }

          ui.row.className = 'rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-2 min-w-0';
          ui.size.style.display = 'none';
          ui.barWrap.style.display = 'none';
          ui.state.textContent = formatBytes(file.size);
          ui.state.className = 'text-[11px] text-sage mt-1';
          resolve(payload.uploadId);
          return;
        }

        const payload = xhr.response as { error?: string } | null;
        reject(new Error(payload?.error?.trim() || 'Upload failed.'));
      });

      xhr.addEventListener('abort', () => {
        activeXhr = null;
        reject(new Error('Upload canceled.'));
      });

      xhr.addEventListener('error', () => {
        activeXhr = null;
        reject(new Error('Upload failed.'));
      });

      const formData = new FormData();
      formData.append('draftShareId', draftShareId);
      formData.append('file', file, file.name);
      xhr.send(formData);
    });
  };

  const queueCleanupJob = async (): Promise<void> => {
    const formData = new FormData();
    formData.append('draftShareId', draftShareId);

    try {
      await fetch('/api/uploads/cancel', { method: 'POST', body: formData, credentials: 'same-origin' });
      setStatus('Upload canceled. Cleanup queued in background.', false);
    } catch {
      setStatus('Upload canceled. Cleanup request failed; please retry.', true);
    }
  };

  const queueAndUpload = async (files: FileList | File[] | null | undefined): Promise<void> => {
    if (isUploading) return;

    const selected = Array.from(files ?? []);
    if (selected.length === 0) return;

    const result = validateFileSelection(selected, limits, 0, 0);
    if (!result.ok) {
      showLimitDialog(result.message);
      return;
    }

    uploadList.innerHTML = '';
    cancelRequested = false;
    setControls(true);
    const cards = selected.map((file) => ({ file, ui: createUploadRow(file) }));

    setStatus(`Uploading ${cards.length} file(s)...`, false);
    try {
      for (const card of cards) {
        if (cancelRequested) {
          markCanceledCard(card.ui);
          continue;
        }

        await uploadSingleFile(card.file, card.ui);
      }

      if (cancelRequested) {
        cards.forEach((card) => {
          if (card.ui.state.className.includes('text-sage')) {
            card.ui.state.textContent = 'Canceled (cleanup queued)';
            card.ui.state.className = 'text-[11px] text-ink-muted mt-1';
            card.ui.row.className = 'rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0';
          } else if (!card.ui.state.className.includes('text-danger')) {
            markCanceledCard(card.ui);
          }
        });
        await queueCleanupJob();
        return;
      }

      setStatus('Upload complete. Redirecting to share setup...', false);
      window.location.href = `/shares/new?draftShareId=${encodeURIComponent(draftShareId)}`;
    } catch (error) {
      if (cancelRequested) {
        await queueCleanupJob();
        return;
      }

      setStatus(error instanceof Error ? error.message : 'Upload failed.', true);
    } finally {
      setControls(false);
      activeXhr = null;
    }
  };

  cancelButton.addEventListener('click', () => {
    if (!isUploading || cancelRequested) return;
    cancelRequested = true;
    cancelButton.disabled = true;
    cancelButton.title = 'Canceling upload...';
    setStatus('Canceling upload...', false);
    activeXhr?.abort();
  });

  pickButton.addEventListener('click', (event) => {
    event.stopPropagation();
    if (isUploading) return;
    fileInput.click();
  });
  dropzone.addEventListener('click', () => {
    if (isUploading) return;
    fileInput.click();
  });
  dropzone.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    if (isUploading) return;
    fileInput.click();
  });

  fileInput.addEventListener('change', () => {
    queueAndUpload(fileInput.files);
    fileInput.value = '';
  });

  dropzone.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropzone.classList.add('ring-2', 'ring-terra/40');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('ring-2', 'ring-terra/40'));
  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('ring-2', 'ring-terra/40');
    queueAndUpload(event.dataTransfer?.files || []);
  });

  setControls(false);
})();
