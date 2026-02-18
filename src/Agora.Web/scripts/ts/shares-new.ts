type UploadStageResponse = {
  uploadId?: string;
};

type UploadUi = {
  row: HTMLLIElement;
  remove: HTMLButtonElement;
  size: HTMLParagraphElement;
  barWrap: HTMLDivElement;
  bar: HTMLDivElement;
  state: HTMLParagraphElement;
};

(() => {
  const form = document.querySelector<HTMLFormElement>('[data-share-form]');
  if (!form) return;

  const fileInput = form.querySelector<HTMLInputElement>('[data-file-input]');
  const pickButton = form.querySelector<HTMLButtonElement>('[data-pick-files]');
  const list = form.querySelector<HTMLUListElement>('[data-upload-list]');
  const hidden = form.querySelector<HTMLElement>('[data-upload-hidden]');
  const status = form.querySelector<HTMLElement>('[data-upload-status]');
  const submit = form.querySelector<HTMLButtonElement>('[data-submit]');
  const submitPending = form.querySelector<HTMLElement>('[data-submit-pending]');
  const dropzone = form.querySelector<HTMLElement>('[data-dropzone]');
  const expiryModeInput = form.querySelector<HTMLSelectElement>('[name="expiryMode"]');
  const expiresAtInput = form.querySelector<HTMLInputElement>('[name="expiresAtUtc"]');
  const accountDefaultExpiryInput = form.querySelector<HTMLInputElement>('[data-account-default-expiry-mode]');
  const optionsToggle = form.querySelector<HTMLButtonElement>('[data-options-toggle]');
  const optionsHeader = form.querySelector<HTMLElement>('[data-options-header]');
  const optionsToggleLabel = form.querySelector<HTMLElement>('[data-options-toggle-label]');
  const optionsToggleIcon = form.querySelector<HTMLElement>('[data-options-icon]');
  const optionsPanel = form.querySelector<HTMLElement>('[data-options-panel]');
  const shareTokenInput = form.querySelector<HTMLInputElement>('[data-share-token]');
  const downloadPasswordInput = form.querySelector<HTMLInputElement>('[name="downloadPassword"]');
  const suggestedShareTokenButton = form.querySelector<HTMLButtonElement>('[data-suggested-share-token]');
  const draftShareIdInput = form.querySelector<HTMLInputElement>('[data-draft-share-id]');
  const removeDialog = form.querySelector<HTMLDialogElement>('[data-upload-remove-dialog]');
  const removeNameNode = form.querySelector<HTMLElement>('[data-upload-remove-file-name]');
  const removeCancelButton = form.querySelector<HTMLButtonElement>('[data-upload-remove-cancel]');
  const removeConfirmButton = form.querySelector<HTMLButtonElement>('[data-upload-remove-confirm]');

  if (!fileInput || !pickButton || !list || !hidden || !status || !submit || !draftShareIdInput) return;

  const maxFileSizeBytes = Number(form.dataset.maxFileSizeBytes || '0');
  const maxTotalUploadBytes = Number(form.dataset.maxTotalUploadBytes || '0');
  const uploadedIds = new Set<string>();

  hidden.querySelectorAll<HTMLInputElement>('input[name="uploadedFileIds"]').forEach((input) => {
    if (input.value) uploadedIds.add(input.value);
  });

  let activeUploads = 0;
  let manualExpiryValue = '';
  let pendingRemoval: { id: string; row: Element | null } | null = null;
  let isSubmitting = false;

  const optionsStorageKey = 'agora:new-share:options-collapsed';
  const pickPrimaryClass = 'px-4 py-2 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors';
  const pickSecondaryClass = 'px-4 py-2 bg-cream text-ink text-sm font-medium rounded-lg border border-border hover:bg-cream-dark/70 transition-colors';

  const setOptionsCollapsed = (isCollapsed: boolean): void => {
    if (!optionsPanel || !optionsToggle) return;
    optionsPanel.classList.toggle('hidden', isCollapsed);
    if (optionsToggleLabel) optionsToggleLabel.textContent = isCollapsed ? 'Show options' : 'Hide options';
    if (optionsToggleIcon) optionsToggleIcon.classList.toggle('rotate-180', !isCollapsed);
    optionsToggle.setAttribute('aria-expanded', String(!isCollapsed));
    optionsHeader?.setAttribute('aria-expanded', String(!isCollapsed));
  };

  const toggleOptions = (): void => {
    if (!optionsPanel) return;
    const nextCollapsed = !optionsPanel.classList.contains('hidden');
    setOptionsCollapsed(nextCollapsed);
    try {
      localStorage.setItem(optionsStorageKey, nextCollapsed ? 'collapsed' : 'expanded');
    } catch {
      // Ignore localStorage access errors.
    }
  };

  const toLocalDateTimeValue = (date: Date): string => {
    const pad = (n: number) => String(n).padStart(2, '0');
    return [
      date.getFullYear(),
      '-',
      pad(date.getMonth() + 1),
      '-',
      pad(date.getDate()),
      'T',
      pad(date.getHours()),
      ':',
      pad(date.getMinutes())
    ].join('');
  };

  const formatLimitBytes = (bytes: number): string => {
    if (!Number.isFinite(bytes) || bytes <= 0) return '';
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const formatBytes = (bytes: number): string => {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} B`;
  };

  const resolveEffectiveExpiryMode = (): string => {
    const selected = (expiryModeInput?.value || 'account_default').trim().toLowerCase();
    if (selected !== 'account_default') return selected;
    return (accountDefaultExpiryInput?.value || '7_days').trim().toLowerCase();
  };

  const computeExpiryDate = (mode: string, now: Date): Date | null => {
    switch (mode) {
      case '1_hour':
        return new Date(now.getTime() + 1 * 60 * 60 * 1000);
      case '24_hours':
        return new Date(now.getTime() + 24 * 60 * 60 * 1000);
      case '7_days':
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      case '30_days':
        return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      case '1_year': {
        const d = new Date(now.getTime());
        d.setFullYear(d.getFullYear() + 1);
        return d;
      }
      default:
        return null;
    }
  };

  const syncExpiryInput = (): void => {
    if (!expiresAtInput) return;
    const effectiveMode = resolveEffectiveExpiryMode();
    const now = new Date();
    const isManualDate = effectiveMode === 'date';

    if (isManualDate) {
      expiresAtInput.disabled = false;
      const parsed = expiresAtInput.value ? new Date(expiresAtInput.value) : null;
      if (parsed && !Number.isNaN(parsed.getTime()) && parsed.getTime() > now.getTime()) {
        manualExpiryValue = expiresAtInput.value;
      }
      if (!manualExpiryValue) {
        manualExpiryValue = toLocalDateTimeValue(new Date(now.getTime() + 24 * 60 * 60 * 1000));
      }
      expiresAtInput.value = manualExpiryValue;
      expiresAtInput.title = '';
      return;
    }

    if (!expiresAtInput.disabled && expiresAtInput.value) {
      manualExpiryValue = expiresAtInput.value;
    }

    expiresAtInput.disabled = true;
    const calculated = computeExpiryDate(effectiveMode, now);
    if (!calculated) {
      expiresAtInput.value = '';
      expiresAtInput.title = effectiveMode === 'indefinite' ? 'No expiry date for indefinite mode.' : 'Calculated from expiry mode.';
      return;
    }

    expiresAtInput.value = toLocalDateTimeValue(calculated);
    expiresAtInput.title = 'Calculated from expiry mode.';
  };

  const refreshState = (): void => {
    if (isSubmitting) {
      submit.disabled = true;
      submit.title = 'Preparing your link...';
      return;
    }

    const hasUploadedFiles = uploadedIds.size > 0;
    pickButton.className = hasUploadedFiles ? pickSecondaryClass : pickPrimaryClass;
    pickButton.textContent = hasUploadedFiles ? 'Add more files' : 'Select files';

    syncExpiryInput();
    const effectiveExpiryMode = resolveEffectiveExpiryMode();
    let reason = '';

    if (activeUploads > 0) reason = 'Please wait for uploads to finish.';
    else if (uploadedIds.size === 0) reason = 'Upload at least one file first.';
    else if (shareTokenInput) {
      const token = (shareTokenInput.value || '').trim();
      if (token.length < 3 || token.length > 64 || !/^[A-Za-z0-9_-]+$/.test(token)) {
        reason = 'Share link must be 3-64 letters, numbers, hyphens, or underscores.';
      }
    }

    if (!reason && downloadPasswordInput) {
      const value = (downloadPasswordInput.value || '').trim();
      if (value.length > 0 && value.length < 8) {
        reason = 'Download password must be at least 8 characters.';
      }
    }

    if (!reason && effectiveExpiryMode === 'date') {
      if (!expiresAtInput?.value) reason = 'Pick an expiry date and time.';
      else {
        const value = new Date(expiresAtInput.value).getTime();
        if (Number.isNaN(value) || value <= Date.now()) {
          reason = 'Expiry date must be in the future.';
        }
      }
    }

    submit.disabled = reason.length > 0;
    submit.title = reason;

    if (activeUploads > 0) {
      status.textContent = `Uploading ${activeUploads} file(s)...`;
      return;
    }
    status.textContent = uploadedIds.size > 0 ? `${uploadedIds.size} file(s) uploaded and ready.` : 'No files uploaded yet.';
  };

  const addHidden = (id: string): void => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'uploadedFileIds';
    input.value = id;
    input.setAttribute('data-uploaded-file-id', id);
    hidden.appendChild(input);
  };

  const removeHidden = (id: string): void => {
    hidden.querySelectorAll<HTMLInputElement>('input[name="uploadedFileIds"]').forEach((input) => {
      if (input.value === id) input.remove();
    });
  };

  const executeRemove = (id: string, row: Element | null): void => {
    if (!id) return;
    const data = new FormData();
    data.append('uploadId', id);
    data.append('draftShareId', draftShareIdInput.value);

    fetch('/api/uploads/remove', { method: 'POST', body: data })
      .then((response) => {
        if (!response.ok) throw new Error();
        uploadedIds.delete(id);
        removeHidden(id);
        row?.remove();
        refreshState();
      })
      .catch(() => {
        status.textContent = 'Unable to remove file right now.';
      });
  };

  const requestRemove = (id: string, row: Element | null): void => {
    if (!id) return;

    pendingRemoval = { id, row };
    if (removeNameNode) {
      const fileNameNode = row?.querySelector('p');
      removeNameNode.textContent = (fileNameNode?.textContent || '').trim() || 'this file';
    }

    if (removeDialog && typeof removeDialog.showModal === 'function') {
      removeDialog.showModal();
      return;
    }

    executeRemove(id, row);
  };

  const createRow = (file: File): UploadUi => {
    const row = document.createElement('li');
    row.className = 'relative rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0';

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'absolute right-1 top-1 p-0.5 text-ink-muted hover:text-danger leading-none text-sm font-semibold hidden';
    remove.textContent = 'x';
    remove.title = 'Remove file';

    const name = document.createElement('p');
    name.className = 'text-xs text-ink-light truncate pr-6';
    name.textContent = file.name;

    const size = document.createElement('p');
    size.className = 'text-[11px] text-ink-muted mt-0.5';
    size.textContent = formatBytes(file.size);

    const barWrap = document.createElement('div');
    barWrap.className = 'mt-1.5 h-1 bg-white rounded-full overflow-hidden';

    const bar = document.createElement('div');
    bar.className = 'h-full bg-terra transition-all';
    bar.style.width = '0%';
    barWrap.appendChild(bar);

    const state = document.createElement('p');
    state.className = 'text-[11px] text-ink-muted mt-1';
    state.textContent = 'Queued...';

    row.append(remove, name, size, barWrap, state);
    list.appendChild(row);

    return { row, remove, size, barWrap, bar, state };
  };

  const resolveUploadErrorMessage = (xhr: XMLHttpRequest): string => {
    if (xhr.status === 413) {
      return 'Upload failed: file is larger than the server request limit.';
    }

    const payload = xhr.response as { error?: string } | null;
    if (payload && typeof payload.error === 'string' && payload.error.trim()) {
      return payload.error.trim();
    }

    const text = (xhr.responseText || '').trim();
    if (text.length > 0) {
      try {
        const parsed = JSON.parse(text) as { error?: string };
        if (parsed?.error?.trim()) {
          return parsed.error.trim();
        }
      } catch {
        return text.length <= 180 ? text : `${text.slice(0, 180)}...`;
      }
    }

    return 'Upload failed.';
  };

  const uploadFile = (file: File): void => {
    const ui = createRow(file);
    activeUploads += 1;
    refreshState();

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/uploads/stage');
    xhr.responseType = 'json';

    xhr.upload.addEventListener('progress', (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.min(100, Math.round((event.loaded / event.total) * 100));
      ui.bar.style.width = `${percent}%`;
      ui.state.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
    });

    xhr.addEventListener('load', () => {
      activeUploads -= 1;
      const response = xhr.response as UploadStageResponse | null;
      if (xhr.status >= 200 && xhr.status < 300 && response?.uploadId) {
        const id = response.uploadId;
        uploadedIds.add(id);
        addHidden(id);
        ui.row.setAttribute('data-upload-id', id);
        ui.row.setAttribute('data-upload-size-bytes', String(file.size || 0));
        ui.row.className = 'relative rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-1.5 min-w-0';
        ui.size.style.display = 'none';
        ui.barWrap.style.display = 'none';
        ui.state.textContent = formatBytes(file.size);
        ui.state.className = 'text-[11px] text-sage mt-0.5';
        ui.remove.classList.remove('hidden');
        ui.remove.addEventListener('click', () => requestRemove(id, ui.row));
      } else {
        const errorMessage = resolveUploadErrorMessage(xhr);
        ui.row.className = 'relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
        ui.bar.className = 'h-full bg-danger';
        ui.state.textContent = errorMessage;
        ui.state.className = 'text-[11px] text-danger mt-1';
        status.textContent = errorMessage;
      }
      refreshState();
    });

    xhr.addEventListener('error', () => {
      activeUploads -= 1;
      const errorMessage = resolveUploadErrorMessage(xhr);
      ui.row.className = 'relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
      ui.bar.className = 'h-full bg-danger';
      ui.state.textContent = errorMessage;
      ui.state.className = 'text-[11px] text-danger mt-1';
      status.textContent = errorMessage;
      refreshState();
    });

    const data = new FormData();
    data.append('draftShareId', draftShareIdInput.value);
    data.append('file', file, file.name);
    xhr.send(data);
  };

  list.querySelectorAll<HTMLButtonElement>('[data-upload-remove]').forEach((button) => {
    button.addEventListener('click', () => {
      const row = button.closest<HTMLElement>('[data-upload-id]');
      const id = row?.getAttribute('data-upload-id') || '';
      if (!id) return;
      requestRemove(id, row);
    });
  });

  removeCancelButton?.addEventListener('click', () => {
    pendingRemoval = null;
    removeDialog?.close();
  });

  removeConfirmButton?.addEventListener('click', () => {
    if (pendingRemoval) {
      executeRemove(pendingRemoval.id, pendingRemoval.row);
    }
    pendingRemoval = null;
    removeDialog?.close();
  });

  const queueSelectedFiles = (files: FileList | File[] | null | undefined): void => {
    const selected = Array.from(files ?? []);
    const existingBytes = Array.from(list.querySelectorAll<HTMLElement>('[data-upload-size-bytes]'))
      .map((row) => Number(row.getAttribute('data-upload-size-bytes') || '0'))
      .filter((value) => Number.isFinite(value) && value > 0)
      .reduce((sum, value) => sum + value, 0);

    let pendingBytes = 0;
    selected.forEach((file) => {
      if (maxFileSizeBytes > 0 && file.size > maxFileSizeBytes) {
        status.textContent = `Upload failed: "${file.name}" exceeds per-file limit (${formatLimitBytes(maxFileSizeBytes)}).`;
        return;
      }

      if (maxTotalUploadBytes > 0 && existingBytes + pendingBytes + file.size > maxTotalUploadBytes) {
        status.textContent = `Upload failed: adding "${file.name}" exceeds total upload limit (${formatLimitBytes(maxTotalUploadBytes)}).`;
        return;
      }

      pendingBytes += file.size;
      uploadFile(file);
    });
  };

  pickButton.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    queueSelectedFiles(fileInput.files || []);
    fileInput.value = '';
  });

  dropzone?.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropzone.classList.add('ring-2', 'ring-terra/40');
  });
  dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('ring-2', 'ring-terra/40'));
  dropzone?.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('ring-2', 'ring-terra/40');
    queueSelectedFiles(event.dataTransfer?.files || []);
  });

  expiryModeInput?.addEventListener('change', refreshState);
  expiresAtInput?.addEventListener('input', refreshState);
  shareTokenInput?.addEventListener('input', refreshState);
  downloadPasswordInput?.addEventListener('input', refreshState);

  suggestedShareTokenButton?.addEventListener('click', () => {
    if (!shareTokenInput) return;
    shareTokenInput.value = suggestedShareTokenButton.getAttribute('data-suggested-share-token') || shareTokenInput.value;
    shareTokenInput.focus();
    shareTokenInput.select();
    refreshState();
  });

  if (optionsPanel && optionsToggle) {
    let isCollapsed = true;
    try {
      const saved = localStorage.getItem(optionsStorageKey);
      if (saved === 'expanded') isCollapsed = false;
      else if (saved === 'collapsed') isCollapsed = true;
    } catch {
      // Ignore localStorage access errors.
    }

    setOptionsCollapsed(isCollapsed);
    optionsToggle.addEventListener('click', (event) => {
      event.stopPropagation();
      toggleOptions();
    });

    optionsHeader?.addEventListener('click', (event) => {
      if ((event.target as HTMLElement | null)?.closest('[data-options-toggle]')) return;
      toggleOptions();
    });

    optionsHeader?.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      toggleOptions();
    });
  }

  form.addEventListener('submit', (event) => {
    if (submit.disabled || isSubmitting) {
      event.preventDefault();
      return;
    }

    isSubmitting = true;
    submit.disabled = true;
    submit.title = 'Preparing your link...';
    submit.textContent = 'Preparing your link...';
    submitPending?.classList.remove('hidden');
    form.setAttribute('aria-busy', 'true');
    fileInput.disabled = true;
    pickButton.disabled = true;
    optionsToggle?.setAttribute('disabled', 'disabled');
    shareTokenInput?.setAttribute('readonly', 'readonly');
    downloadPasswordInput?.setAttribute('readonly', 'readonly');
    refreshState();
  });

  const modeInput = form.querySelector<HTMLSelectElement>('[data-template-mode]');
  const summary = form.querySelector<HTMLElement>('[data-template-summary]');
  const titleInput = form.querySelector<HTMLInputElement>('[data-template-title]');
  const h1Input = form.querySelector<HTMLInputElement>('[data-template-h1]');
  const customActions = form.querySelector<HTMLElement>('[data-template-custom-actions]');
  const designerLink = form.querySelector<HTMLAnchorElement>('[data-template-designer-link]');

  const refreshTemplateMode = (): void => {
    if (!modeInput) return;
    if (modeInput.value !== 'per_upload') {
      if (summary) summary.textContent = 'Using account default template.';
      customActions?.classList.add('hidden');
      return;
    }

    if (summary) {
      summary.textContent = `Custom design selected: ${h1Input?.value || titleInput?.value || 'Untitled'}.`;
    }
    customActions?.classList.remove('hidden');
  };

  designerLink?.addEventListener('click', (event) => {
    if (modeInput?.value !== 'per_upload') event.preventDefault();
  });
  modeInput?.addEventListener('change', refreshTemplateMode);

  refreshTemplateMode();
  refreshState();
})();
