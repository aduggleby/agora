import { readLimitsFromElement, validateFileSelection, formatLimitBytes, showLimitDialog } from './upload-limits';
import { copyText } from './clipboard';

type UploadStageResponse = {
  uploadId?: string;
  fileName?: string;
  sizeBytes?: number;
  directLinkEligible?: boolean;
};

type StagedUploadState = {
  fileName: string;
  sizeBytes: number;
  directLinkEligible: boolean;
};

type DirectLinkResponse = {
  url?: string;
  token?: string;
  expiresAtUtc?: string;
  nextDraftShareId?: string;
  error?: string;
};

type UploadUi = {
  row: HTMLLIElement;
  remove: HTMLButtonElement;
  size: HTMLParagraphElement;
  barWrap: HTMLDivElement;
  bar: HTMLDivElement;
  state: HTMLParagraphElement;
};

type SavedShareOptionsState = {
  showPreviews?: boolean;
  notifyMode?: string;
  expiryMode?: string;
  expiresAtUtc?: string;
  templateMode?: string;
};

(() => {
  const form = document.querySelector<HTMLFormElement>('[data-share-form]');
  if (!form) return;

  const fileInput = form.querySelector<HTMLInputElement>('[data-file-input]');
  const pickButton = form.querySelector<HTMLButtonElement>('[data-pick-files]');
  const cancelUploadsButton = form.querySelector<HTMLButtonElement>('[data-upload-cancel]');
  const list = form.querySelector<HTMLUListElement>('[data-upload-list]');
  const hidden = form.querySelector<HTMLElement>('[data-upload-hidden]');
  const status = form.querySelector<HTMLElement>('[data-upload-status]');
  const submit = form.querySelector<HTMLButtonElement>('[data-submit]');
  const submitPending = form.querySelector<HTMLElement>('[data-submit-pending]');
  const dropzone = form.querySelector<HTMLElement>('[data-dropzone]');
  const expiryModeInput = form.querySelector<HTMLSelectElement>('[name="expiryMode"]');
  const expiresAtInput = form.querySelector<HTMLInputElement>('[name="expiresAtUtc"]');
  const notifyModeInput = form.querySelector<HTMLSelectElement>('[name="notifyMode"]');
  const showPreviewsInput = form.querySelector<HTMLInputElement>('[name="showPreviews"]');
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
  const directLinkButton = form.querySelector<HTMLButtonElement>('[data-direct-link]');
  const directDurationInput = form.querySelector<HTMLSelectElement>('[data-direct-duration]');
  const directResult = form.querySelector<HTMLElement>('[data-direct-link-result]');
  const directResultSuccess = form.querySelector<HTMLElement>('[data-direct-link-success]');
  const directResultUrl = form.querySelector<HTMLAnchorElement>('[data-direct-link-url]');
  const directResultExpiry = form.querySelector<HTMLElement>('[data-direct-link-expiry]');
  const directResultNotice = form.querySelector<HTMLElement>('[data-direct-link-notice]');
  const directResultCopy = form.querySelector<HTMLButtonElement>('[data-direct-link-copy]');
  const directResultError = form.querySelector<HTMLElement>('[data-direct-link-error]');

  if (!fileInput || !pickButton || !cancelUploadsButton || !list || !hidden || !status || !submit || !draftShareIdInput) return;

  const limits = readLimitsFromElement(form);
  const uploadedIds = new Set<string>();
  // Per-upload state from the stage response (or the server-rendered rows), keyed by upload id.
  const uploads = new Map<string, StagedUploadState>();

  hidden.querySelectorAll<HTMLInputElement>('input[name="uploadedFileIds"]').forEach((input) => {
    if (input.value) uploadedIds.add(input.value);
  });
  list.querySelectorAll<HTMLElement>('[data-upload-id]').forEach((row) => {
    const id = row.getAttribute('data-upload-id') || '';
    if (!id) return;
    uploads.set(id, {
      fileName: row.getAttribute('data-upload-file-name') || '',
      sizeBytes: Number(row.getAttribute('data-upload-size-bytes') || '0'),
      directLinkEligible: row.getAttribute('data-direct-link-eligible') === 'true'
    });
  });

  let activeUploads = 0;
  let manualExpiryValue = '';
  let pendingRemoval: { id: string; row: Element | null } | null = null;
  let isSubmitting = false;
  let isCreatingDirectLink = false;
  let cancelRequested = false;
  let directLinkUrl = '';
  const activeRequests = new Set<XMLHttpRequest>();
  const directDurationStorageKey = 'agora.directLink.duration';
  const allowedDirectDurations = new Set(['30m', '6h', '1d', '7d']);

  const optionsStorageKey = 'agora:new-share:options-collapsed';
  const optionsStateStoragePrefix = 'agora:new-share:options-state:';
  let optionsStateStorageKey = `${optionsStateStoragePrefix}${draftShareIdInput.value.trim()}`;
  const pickPrimaryClass = 'px-4 py-2 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors';
  const pickSecondaryClass = 'px-4 py-2 bg-cream text-ink text-sm font-medium rounded-lg border border-border hover:bg-cream-dark/70 transition-colors';
  const allowedNotifyModes = new Set(['account_default', 'none', 'once', 'every_time']);
  const allowedExpiryModes = new Set(['account_default', '1_hour', '24_hours', '7_days', '30_days', '1_year', 'date', 'indefinite']);
  const allowedTemplateModes = new Set(['account_default', 'per_upload']);

  const saveOptionsState = (): void => {
    const state: SavedShareOptionsState = {
      showPreviews: showPreviewsInput?.checked === true,
      notifyMode: notifyModeInput?.value || 'account_default',
      expiryMode: expiryModeInput?.value || 'account_default',
      expiresAtUtc: expiresAtInput?.value || '',
      templateMode: form.querySelector<HTMLSelectElement>('[data-template-mode]')?.value || 'account_default'
    };

    try {
      localStorage.setItem(optionsStateStorageKey, JSON.stringify(state));
    } catch {
      // Ignore localStorage access errors.
    }
  };

  const restoreOptionsState = (): void => {
    let state: SavedShareOptionsState | null = null;
    try {
      const raw = localStorage.getItem(optionsStateStorageKey);
      if (!raw) return;
      state = JSON.parse(raw) as SavedShareOptionsState;
    } catch {
      state = null;
    }

    if (!state) return;

    if (showPreviewsInput && typeof state.showPreviews === 'boolean') {
      showPreviewsInput.checked = state.showPreviews;
    }

    if (notifyModeInput && state.notifyMode && allowedNotifyModes.has(state.notifyMode)) {
      notifyModeInput.value = state.notifyMode;
    }

    if (expiryModeInput && state.expiryMode && allowedExpiryModes.has(state.expiryMode)) {
      expiryModeInput.value = state.expiryMode;
    }

    if (expiresAtInput && typeof state.expiresAtUtc === 'string' && state.expiresAtUtc.trim()) {
      expiresAtInput.value = state.expiresAtUtc.trim();
      manualExpiryValue = expiresAtInput.value;
    }

    const templateModeInput = form.querySelector<HTMLSelectElement>('[data-template-mode]');
    if (templateModeInput && state.templateMode && allowedTemplateModes.has(state.templateMode)) {
      templateModeInput.value = state.templateMode;
    }
  };

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

  const directLinkDisabledReason = (): string => {
    if (isSubmitting) return 'Preparing your link...';
    if (isCreatingDirectLink) return 'Creating your direct link...';
    if (activeUploads > 0) return 'Please wait for uploads to finish.';
    if (uploadedIds.size === 0) return 'Upload one file first.';
    if (uploadedIds.size > 1) return 'A direct link can hold only one file; remove the others or create a share link.';
    const [onlyId] = Array.from(uploadedIds);
    const state = uploads.get(onlyId);
    if (!state || !state.directLinkEligible) return 'This file type can only be downloaded, not opened directly; create a share link instead.';
    return '';
  };

  // While a direct link is being created the draft is about to be finalized and replaced: nothing may be staged
  // into, or removed from, it until the replacement draft is in place.
  const setDraftLocked = (locked: boolean): void => {
    fileInput.disabled = locked;
    pickButton.disabled = locked;
    pickButton.title = locked ? 'Creating your direct link...' : '';
    list.querySelectorAll<HTMLButtonElement>('[data-upload-remove]').forEach((button) => {
      button.disabled = locked;
      button.title = locked ? 'Creating your direct link...' : 'Remove file';
    });
    if (locked) {
      cancelUploadsButton.disabled = true;
      cancelUploadsButton.title = 'Creating your direct link...';
    }
  };

  const refreshDirectLinkState = (): void => {
    if (!directLinkButton) return;
    const reason = directLinkDisabledReason();
    directLinkButton.disabled = reason.length > 0;
    directLinkButton.title = reason || 'Create a link that opens this file directly, without a download page.';
    if (directDurationInput) directDurationInput.disabled = isSubmitting || isCreatingDirectLink;
  };

  const refreshState = (): void => {
    refreshDirectLinkState();
    if (isSubmitting) {
      submit.disabled = true;
      submit.title = 'Preparing your link...';
      return;
    }

    if (isCreatingDirectLink) {
      submit.disabled = true;
      submit.title = 'Creating your direct link...';
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
      if (token.length < 8 || token.length > 64 || !/^[A-Za-z0-9_-]+$/.test(token)) {
        reason = 'Share link must be 8-64 letters, numbers, hyphens, or underscores.';
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
      cancelUploadsButton.classList.remove('hidden');
      cancelUploadsButton.disabled = false;
      cancelUploadsButton.title = 'Cancel upload and queue immediate cleanup.';
      return;
    }

    cancelUploadsButton.classList.add('hidden');
    cancelUploadsButton.disabled = true;
    cancelUploadsButton.title = 'No upload is currently running.';
    status.textContent = uploadedIds.size > 0 ? `${uploadedIds.size} file(s) uploaded and ready.` : 'No files uploaded yet.';
  };

  const markCanceledUi = (ui: UploadUi, detail?: string): void => {
    ui.row.className = 'relative rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0';
    ui.barWrap.style.display = 'none';
    ui.state.textContent = detail || 'Canceled';
    ui.state.className = 'text-[11px] text-ink-muted mt-1';
    ui.remove.classList.add('hidden');
  };

  const queueDraftCleanup = async (): Promise<void> => {
    const data = new FormData();
    data.append('draftShareId', draftShareIdInput.value);
    try {
      const response = await fetch('/api/uploads/cancel', { method: 'POST', body: data, credentials: 'same-origin' });
      if (!response.ok) throw new Error();
      status.textContent = 'Upload canceled. Cleanup queued in background.';
    } catch {
      status.textContent = 'Upload canceled. Cleanup request failed; please retry.';
    }
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
    if (!id || isCreatingDirectLink) return;
    const data = new FormData();
    data.append('uploadId', id);
    data.append('draftShareId', draftShareIdInput.value);

    fetch('/api/uploads/remove', { method: 'POST', body: data })
      .then((response) => {
        if (!response.ok) throw new Error();
        uploadedIds.delete(id);
        uploads.delete(id);
        removeHidden(id);
        row?.remove();
        refreshState();
      })
      .catch(() => {
        status.textContent = 'Unable to remove file right now.';
      });
  };

  const requestRemove = (id: string, row: Element | null): void => {
    if (!id || isCreatingDirectLink) return;

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
    remove.setAttribute('data-upload-remove', '');

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
    state.textContent = 'Pending';

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
    activeRequests.add(xhr);
    // Draft id travels in the query string so the server can run admission checks before reading the body.
    xhr.open('POST', `/api/uploads/stage?draftShareId=${encodeURIComponent(draftShareIdInput.value)}`);
    xhr.responseType = 'json';
    let settled = false;
    const finalize = (): void => {
      if (settled) return;
      settled = true;
      activeRequests.delete(xhr);
      activeUploads = Math.max(0, activeUploads - 1);
      refreshState();
    };

    xhr.upload.addEventListener('progress', (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.min(100, Math.round((event.loaded / event.total) * 100));
      ui.bar.style.width = `${percent}%`;
      ui.state.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
    });

    xhr.addEventListener('load', () => {
      finalize();
      const response = xhr.response as UploadStageResponse | null;
      if (cancelRequested) {
        markCanceledUi(ui, 'Canceled (cleanup queued)');
        return;
      }

      if (xhr.status >= 200 && xhr.status < 300 && response?.uploadId) {
        const id = response.uploadId;
        uploadedIds.add(id);
        uploads.set(id, {
          fileName: response.fileName || file.name,
          sizeBytes: typeof response.sizeBytes === 'number' ? response.sizeBytes : file.size,
          directLinkEligible: response.directLinkEligible === true
        });
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
        refreshState();
      } else {
        const errorMessage = resolveUploadErrorMessage(xhr);
        ui.row.className = 'relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
        ui.bar.className = 'h-full bg-danger';
        ui.state.textContent = errorMessage;
        ui.state.className = 'text-[11px] text-danger mt-1';
        status.textContent = errorMessage;
      }
    });

    xhr.addEventListener('abort', () => {
      finalize();
      markCanceledUi(ui);
    });

    xhr.addEventListener('error', () => {
      finalize();
      if (cancelRequested) {
        markCanceledUi(ui);
        return;
      }
      const errorMessage = resolveUploadErrorMessage(xhr);
      ui.row.className = 'relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
      ui.bar.className = 'h-full bg-danger';
      ui.state.textContent = errorMessage;
      ui.state.className = 'text-[11px] text-danger mt-1';
      status.textContent = errorMessage;
    });

    const data = new FormData();
    data.append('draftShareId', draftShareIdInput.value);
    data.append('file', file, file.name);
    xhr.send(data);
  };

  cancelUploadsButton.addEventListener('click', async () => {
    if (activeUploads <= 0 || cancelRequested) return;
    cancelRequested = true;
    cancelUploadsButton.disabled = true;
    cancelUploadsButton.title = 'Canceling upload...';
    status.textContent = 'Canceling upload...';

    uploadedIds.clear();
    uploads.clear();
    hidden.querySelectorAll<HTMLInputElement>('input[name="uploadedFileIds"]').forEach((input) => input.remove());

    activeRequests.forEach((request) => request.abort());
    await queueDraftCleanup();
    cancelRequested = false;
    refreshState();
  });

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
    // Drops and picks that land while the draft is being replaced are ignored: they would stage into a draft
    // that is being finalized.
    if (isCreatingDirectLink) return;
    const selected = Array.from(files ?? []);
    if (selected.length === 0) return;
    cancelRequested = false;

    const currentFileCount = uploadedIds.size + activeUploads;
    const currentTotalBytes = Array.from(list.querySelectorAll<HTMLElement>('[data-upload-size-bytes]'))
      .map((row) => Number(row.getAttribute('data-upload-size-bytes') || '0'))
      .filter((value) => Number.isFinite(value) && value > 0)
      .reduce((sum, value) => sum + value, 0);

    const result = validateFileSelection(selected, limits, currentFileCount, currentTotalBytes);
    if (!result.ok) {
      showLimitDialog(result.message);
      return;
    }

    selected.forEach((file) => uploadFile(file));
  };

  pickButton.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    queueSelectedFiles(fileInput.files || []);
    fileInput.value = '';
  });

  dropzone?.addEventListener('dragover', (event) => {
    event.preventDefault();
    if (isCreatingDirectLink) return;
    dropzone.classList.add('ring-2', 'ring-terra/40');
  });
  dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('ring-2', 'ring-terra/40'));
  dropzone?.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('ring-2', 'ring-terra/40');
    queueSelectedFiles(event.dataTransfer?.files || []);
  });

  expiryModeInput?.addEventListener('change', refreshState);
  expiryModeInput?.addEventListener('change', saveOptionsState);
  expiresAtInput?.addEventListener('input', refreshState);
  expiresAtInput?.addEventListener('input', saveOptionsState);
  notifyModeInput?.addEventListener('change', saveOptionsState);
  showPreviewsInput?.addEventListener('change', saveOptionsState);
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
    else saveOptionsState();
  });
  modeInput?.addEventListener('change', () => {
    refreshTemplateMode();
    saveOptionsState();
  });

  const restoreDirectDuration = (): void => {
    if (!directDurationInput) return;
    try {
      const saved = (localStorage.getItem(directDurationStorageKey) || '').trim();
      if (saved && allowedDirectDurations.has(saved)) directDurationInput.value = saved;
    } catch {
      // Ignore localStorage access errors.
    }
  };

  directDurationInput?.addEventListener('change', () => {
    try {
      localStorage.setItem(directDurationStorageKey, directDurationInput.value);
    } catch {
      // Ignore localStorage access errors.
    }
  });

  const showDirectLinkError = (message: string): void => {
    if (!directResult) return;
    directResult.classList.remove('hidden');
    directResultSuccess?.classList.add('hidden');
    if (directResultError) {
      directResultError.textContent = message;
      directResultError.classList.remove('hidden');
    }
  };

  const setDirectLinkNotice = (message: string, ok: boolean): void => {
    if (!directResultNotice) return;
    directResultNotice.textContent = message;
    directResultNotice.classList.toggle('text-sage', ok);
    directResultNotice.classList.toggle('text-danger', !ok);
    directResultNotice.classList.remove('hidden');
  };

  const showDirectLinkResult = (url: string, expiresAtUtc: string, copied: boolean): void => {
    if (!directResult) return;
    directLinkUrl = url;
    directResult.classList.remove('hidden');
    directResultError?.classList.add('hidden');
    directResultSuccess?.classList.remove('hidden');
    if (directResultUrl) {
      directResultUrl.href = url;
      directResultUrl.textContent = url;
    }
    if (directResultExpiry) {
      const expires = new Date(expiresAtUtc);
      directResultExpiry.textContent = Number.isNaN(expires.getTime())
        ? ''
        : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(expires);
    }
    setDirectLinkNotice(copied ? 'Copied to clipboard' : 'Could not copy automatically; use the Copy link button.', copied);
  };

  const newDraftShareId = (): string =>
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID().replace(/-/g, '')
      : Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

  // The old draft was finalized by the server (staged files and background gone): the page continues on a clean
  // replacement draft, with the template reset to the account default.
  const replaceDraft = (nextDraftShareId: string): void => {
    const draftShareId = nextDraftShareId || newDraftShareId();
    uploadedIds.clear();
    uploads.clear();
    hidden.querySelectorAll<HTMLInputElement>('input[name="uploadedFileIds"]').forEach((input) => input.remove());
    list.innerHTML = '';

    draftShareIdInput.value = draftShareId;
    optionsStateStorageKey = `${optionsStateStoragePrefix}${draftShareId}`;
    const designer = form.querySelector<HTMLAnchorElement>('[data-template-designer-link]');
    if (designer) designer.href = `/share/landing-page-designer?draftShareId=${encodeURIComponent(draftShareId)}`;
    try {
      window.history.replaceState(null, '', `/shares/new?draftShareId=${encodeURIComponent(draftShareId)}`);
    } catch {
      // Ignore history access errors.
    }

    const templateDefaults: Array<[string, string]> = [
      ['[data-template-title]', ''],
      ['[data-template-h1]', ''],
      ['[data-template-description]', ''],
      ['[data-template-background-upload-id]', ''],
      ['[data-template-background-color-hex]', ''],
      ['[data-template-container-position]', 'center']
    ];
    templateDefaults.forEach(([selector, value]) => {
      const input = form.querySelector<HTMLInputElement>(selector);
      if (input) input.value = value;
    });
    const templateModeInput = form.querySelector<HTMLSelectElement>('[data-template-mode]');
    if (templateModeInput) templateModeInput.value = 'account_default';
    refreshTemplateMode();
  };

  const resolveDirectLinkError = async (response: Response): Promise<string> => {
    try {
      const payload = (await response.json()) as DirectLinkResponse;
      if (payload?.error?.trim()) return payload.error.trim();
    } catch {
      // Not JSON: fall back to the status text.
    }
    return response.status === 413 ? 'Request too large.' : `Could not create the direct link (HTTP ${response.status}).`;
  };

  directLinkButton?.addEventListener('click', async () => {
    if (directLinkButton.disabled || isCreatingDirectLink) return;
    const [uploadId] = Array.from(uploadedIds);
    if (!uploadId) return;

    isCreatingDirectLink = true;
    setDraftLocked(true);
    refreshState();
    try {
      // The CSRF header is added by csrf-client, which has patched fetch by the time a click can happen.
      const response = await fetch('/api/shares/direct-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          draftShareId: draftShareIdInput.value,
          uploadId,
          duration: directDurationInput?.value || '1d'
        })
      });

      if (!response.ok) {
        showDirectLinkError(await resolveDirectLinkError(response));
        return;
      }

      const payload = (await response.json()) as DirectLinkResponse;
      const url = (payload.url || '').trim();
      if (!url) {
        showDirectLinkError('The server did not return a link.');
        return;
      }

      // The draft is replaced before the clipboard write, which may take a while or prompt.
      replaceDraft((payload.nextDraftShareId || '').trim());
      const copied = await copyText(url);
      showDirectLinkResult(url, payload.expiresAtUtc || '', copied);
    } catch {
      showDirectLinkError('Could not create the direct link. Check your connection and try again.');
    } finally {
      isCreatingDirectLink = false;
      setDraftLocked(false);
      refreshState();
    }
  });

  directResultCopy?.addEventListener('click', async () => {
    if (!directLinkUrl) return;
    const copied = await copyText(directLinkUrl);
    setDirectLinkNotice(copied ? 'Copied to clipboard' : 'Could not copy; select the link and copy it manually.', copied);
  });

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


  restoreOptionsState();
  restoreDirectDuration();
  refreshTemplateMode();
  refreshState();
})();
