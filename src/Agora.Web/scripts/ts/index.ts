import { readLimitsFromElement, validateFileSelection, showLimitDialog } from './upload-limits';

(() => {
  const nodes = document.querySelectorAll<HTMLElement>('[data-local-datetime]');
  const formatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  nodes.forEach((node) => {
    const value = node.getAttribute('data-local-datetime');
    if (!value) return;
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
      node.textContent = formatter.format(date);
    }
  });
})();

(() => {
  const dialog = document.querySelector<HTMLDialogElement>('[data-share-delete-dialog]');
  if (!dialog) return;

  const nameNode = dialog.querySelector<HTMLElement>('[data-share-delete-name]');
  const cancelButton = dialog.querySelector<HTMLButtonElement>('[data-share-delete-cancel]');
  const confirmButton = dialog.querySelector<HTMLButtonElement>('[data-share-delete-confirm]');
  let pendingForm: HTMLFormElement | null = null;

  document.querySelectorAll<HTMLElement>('[data-share-delete-trigger]').forEach((button) => {
    button.addEventListener('click', () => {
      const form = button.closest<HTMLFormElement>('[data-share-delete-form]');
      if (!form) return;
      pendingForm = form;
      if (nameNode) {
        nameNode.textContent = form.getAttribute('data-share-name') ?? '';
      }
      dialog.showModal();
    });
  });

  cancelButton?.addEventListener('click', () => dialog.close());
  confirmButton?.addEventListener('click', () => {
    pendingForm?.submit();
    dialog.close();
  });
})();

type ShareFileLike = Record<string, unknown>;

(() => {
  const dialog = document.querySelector<HTMLDialogElement>('[data-share-details-dialog]');
  if (!dialog) return;

  const nameNode = dialog.querySelector<HTMLElement>('[data-share-details-name]');
  const senderNameNode = dialog.querySelector<HTMLElement>('[data-share-details-sender-name]');
  const senderEmailNode = dialog.querySelector<HTMLElement>('[data-share-details-sender-email]');
  const senderMessageNode = dialog.querySelector<HTMLElement>('[data-share-details-sender-message]');
  const listNode = dialog.querySelector<HTMLElement>('[data-share-details-list]');
  const closeButton = dialog.querySelector<HTMLButtonElement>('[data-share-details-close]');
  if (!listNode) return;

  const formatBytes = (bytes: number): string => {
    const value = Number(bytes || 0);
    if (!Number.isFinite(value) || value <= 0) return '0 B';
    if (value >= 1024 * 1024 * 1024) return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
    if (value >= 1024) return `${Math.round(value / 1024)} KB`;
    return `${Math.round(value)} B`;
  };

  const getText = (item: ShareFileLike, key: string): string => {
    const alt = key.charAt(0).toUpperCase() + key.slice(1);
    const value = item[key] ?? item[alt];
    return typeof value === 'string' ? value : '';
  };

  const getNumber = (item: ShareFileLike, key: string): number => {
    const alt = key.charAt(0).toUpperCase() + key.slice(1);
    const value = item[key] ?? item[alt] ?? 0;
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : 0;
  };

  document.querySelectorAll<HTMLElement>('[data-share-details-trigger]').forEach((button) => {
    button.addEventListener('click', () => {
      const shareName = button.getAttribute('data-share-name') ?? '';
      const senderName = (button.getAttribute('data-share-sender-name') ?? '').trim();
      const senderEmail = (button.getAttribute('data-share-sender-email') ?? '').trim();
      const senderMessage = (button.getAttribute('data-share-sender-message') ?? '').trim();
      const raw = button.getAttribute('data-share-files') ?? '[]';

      let files: ShareFileLike[] = [];
      try {
        const parsed = JSON.parse(raw) as unknown;
        files = Array.isArray(parsed) ? (parsed as ShareFileLike[]) : [];
      } catch {
        files = [];
      }

      files.sort((a, b) =>
        getText(a, 'originalFilename').localeCompare(getText(b, 'originalFilename'), undefined, {
          sensitivity: 'base'
        })
      );

      listNode.innerHTML = '';
      files.forEach((file) => {
        const fileName = getText(file, 'originalFilename');
        const fileSize = getNumber(file, 'originalSizeBytes');

        const row = document.createElement('tr');
        row.className = 'border-b border-border/60 last:border-b-0';

        const nameCell = document.createElement('td');
        nameCell.className = 'px-3 py-2 text-sm text-ink-light';
        nameCell.textContent = fileName;

        const sizeCell = document.createElement('td');
        sizeCell.className = 'px-3 py-2 text-sm text-ink-muted text-right';
        sizeCell.textContent = formatBytes(fileSize);

        row.append(nameCell, sizeCell);
        listNode.appendChild(row);
      });

      if (files.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="2" class="px-3 py-3 text-sm text-ink-muted">No file metadata available.</td>';
        listNode.appendChild(row);
      }

      if (nameNode) {
        nameNode.textContent = shareName;
      }
      if (senderNameNode) {
        senderNameNode.textContent = senderName.length > 0 ? `Sender name: ${senderName}` : '';
      }
      if (senderEmailNode) {
        senderEmailNode.textContent = senderEmail.length > 0 ? `Sender email: ${senderEmail}` : '';
      }
      if (senderMessageNode) {
        senderMessageNode.textContent = senderMessage.length > 0 ? `Message:\n${senderMessage}` : '';
      }
      dialog.showModal();
    });
  });

  closeButton?.addEventListener('click', () => dialog.close());
})();

(() => {
  const selectAll = document.querySelector<HTMLInputElement>('[data-received-select-all]');
  if (!selectAll) return;

  const rowCheckboxes = () => Array.from(document.querySelectorAll<HTMLInputElement>('[data-received-select]'));
  const syncSelectAllState = (): void => {
    const checkboxes = rowCheckboxes();
    if (checkboxes.length === 0) {
      selectAll.checked = false;
      selectAll.indeterminate = false;
      return;
    }

    const checkedCount = checkboxes.filter((checkbox) => checkbox.checked).length;
    selectAll.checked = checkedCount === checkboxes.length;
    selectAll.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;
  };

  selectAll.addEventListener('change', () => {
    const shouldCheck = selectAll.checked;
    rowCheckboxes().forEach((checkbox) => {
      checkbox.checked = shouldCheck;
    });
    syncSelectAllState();
  });

  rowCheckboxes().forEach((checkbox) => {
    checkbox.addEventListener('change', syncSelectAllState);
  });
})();

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
        const message = payload?.error?.trim() || 'Upload failed.';
        ui.row.className = 'rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
        ui.state.textContent = message;
        ui.state.className = 'text-[11px] text-danger mt-1';
        reject(new Error(message));
      });

      xhr.addEventListener('abort', () => {
        activeXhr = null;
        reject(new Error('Upload canceled.'));
      });

      xhr.addEventListener('error', () => {
        activeXhr = null;
        ui.row.className = 'rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
        ui.state.textContent = 'Upload failed.';
        ui.state.className = 'text-[11px] text-danger mt-1';
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
          if (card.ui.state.className.includes('text-danger')) return;
          if (card.ui.state.className.includes('text-sage')) {
            card.ui.state.textContent = 'Canceled (cleanup queued)';
            card.ui.state.className = 'text-[11px] text-ink-muted mt-1';
            card.ui.row.className = 'rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0';
          } else {
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
    queueAndUpload(event.dataTransfer?.files ?? []);
  });

  setControls(false);
})();
