import { readLimitsFromElement, validateFileSelection, showLimitDialog } from './upload-limits';

(() => {
  const successScreen = document.querySelector<HTMLElement>('[data-public-upload-success]');
  if (successScreen) {
    runConfetti();
  }

  const form = document.querySelector<HTMLFormElement>('[data-public-upload-form]');
  if (!form) return;

  const fileInput = form.querySelector<HTMLInputElement>('[data-public-file-input]');
  const pickButton = form.querySelector<HTMLButtonElement>('[data-public-pick-files]');
  const dropzone = form.querySelector<HTMLElement>('[data-public-dropzone]');
  const status = form.querySelector<HTMLElement>('[data-public-upload-status]');
  const uploadList = form.querySelector<HTMLUListElement>('[data-public-upload-list]');
  const hidden = form.querySelector<HTMLElement>('[data-public-upload-hidden]');
  const submit = form.querySelector<HTMLButtonElement>('[data-public-submit]');
  const senderNameInput = form.querySelector<HTMLInputElement>('input[name="senderName"]');
  const senderEmailInput = form.querySelector<HTMLInputElement>('input[name="senderEmail"]');
  const senderMessageInput = form.querySelector<HTMLTextAreaElement>('textarea[name="senderMessage"]');
  const uploadToken = form.querySelector<HTMLInputElement>('[data-public-upload-token]')?.value ?? '';
  const draftShareId = form.querySelector<HTMLInputElement>('[data-public-draft-share-id]')?.value ?? '';

  if (!fileInput || !pickButton || !dropzone || !status || !uploadList || !hidden || !submit || !uploadToken || !draftShareId) {
    return;
  }

  const limits = readLimitsFromElement(form);
  const senderNameStorageKey = 'agora:public-upload:sender-name';
  const senderEmailStorageKey = 'agora:public-upload:sender-email';
  const uploadedIds = new Set<string>();
  const uploadedSizes = new Map<string, number>();
  let activeUploads = 0;
  const pickPrimaryClass = 'px-4 py-2 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors';
  const pickSecondaryClass = 'px-4 py-2 bg-cream text-ink text-sm font-medium rounded-lg border border-border hover:bg-cream-dark/70 transition-colors';

  const formatBytes = (bytes: number): string => {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} B`;
  };

  const refreshState = (): void => {
    const hasUploadedFiles = uploadedIds.size > 0;
    const senderEmail = (senderEmailInput?.value || '').trim();
    pickButton.className = hasUploadedFiles ? pickSecondaryClass : pickPrimaryClass;
    pickButton.textContent = hasUploadedFiles ? 'Add more files' : 'Select files';
    submit.classList.toggle('hidden', !hasUploadedFiles);

    let reason = '';
    if (activeUploads > 0) {
      reason = 'Please wait for uploads to finish.';
    } else if (uploadedIds.size === 0) {
      reason = 'Upload at least one file first.';
    } else if (!senderEmail) {
      reason = 'Enter your email first.';
    }

    submit.disabled = reason.length > 0;
    submit.title = reason;

    if (activeUploads > 0) {
      status.textContent = `Uploading ${activeUploads} file(s)...`;
      return;
    }

    status.textContent = uploadedIds.size > 0
      ? `${uploadedIds.size} file(s) uploaded and ready.`
      : 'No files uploaded yet.';
  };

  const restoreSenderFields = (): void => {
    if (!senderNameInput && !senderEmailInput) return;
    try {
      if (senderNameInput && !senderNameInput.value) {
        senderNameInput.value = (localStorage.getItem(senderNameStorageKey) || '').trim();
      }
      if (senderEmailInput && !senderEmailInput.value) {
        senderEmailInput.value = (localStorage.getItem(senderEmailStorageKey) || '').trim();
      }
    } catch {
      // Ignore localStorage access errors.
    }
  };

  const persistSenderFields = (): void => {
    if (!senderNameInput && !senderEmailInput) return;
    try {
      if (senderNameInput) {
        localStorage.setItem(senderNameStorageKey, senderNameInput.value.trim());
      }
      if (senderEmailInput) {
        localStorage.setItem(senderEmailStorageKey, senderEmailInput.value.trim());
      }
    } catch {
      // Ignore localStorage access errors.
    }
  };

  const autoSizeSenderMessage = (): void => {
    if (!senderMessageInput) return;
    senderMessageInput.style.height = 'auto';
    senderMessageInput.style.height = `${Math.max(senderMessageInput.scrollHeight, 96)}px`;
  };

  const createRow = (file: File): { row: HTMLLIElement; bar: HTMLDivElement; note: HTMLParagraphElement } => {
    const row = document.createElement('li');
    row.className = 'rounded-lg border border-border bg-white px-2.5 py-2 min-w-0';

    const name = document.createElement('p');
    name.className = 'text-xs text-ink-light truncate';
    name.textContent = file.name;

    const barWrap = document.createElement('div');
    barWrap.className = 'mt-1.5 h-1 bg-cream-dark rounded-full overflow-hidden';

    const bar = document.createElement('div');
    bar.className = 'h-full bg-terra transition-all';
    bar.style.width = '0%';
    barWrap.appendChild(bar);

    const note = document.createElement('p');
    note.className = 'text-[11px] text-ink-muted mt-1';
    note.textContent = 'Pending';

    row.append(name, barWrap, note);
    uploadList.appendChild(row);
    return { row, bar, note };
  };

  const addHidden = (id: string): void => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'uploadedFileIds';
    input.value = id;
    input.setAttribute('data-uploaded-file-id', id);
    hidden.appendChild(input);
  };

  const uploadSingleFile = (file: File): Promise<void> => {
    const ui = createRow(file);

    return new Promise<void>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/public-uploads/stage');
      xhr.responseType = 'json';

      xhr.upload.addEventListener('progress', (event) => {
        if (!event.lengthComputable) return;
        const percent = Math.min(100, Math.round((event.loaded / event.total) * 100));
        ui.bar.style.width = `${percent}%`;
        ui.note.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          const payload = xhr.response as { uploadId?: string } | null;
          if (!payload?.uploadId) {
            reject(new Error('Upload failed.'));
            return;
          }

          uploadedIds.add(payload.uploadId);
          uploadedSizes.set(payload.uploadId, file.size);
          addHidden(payload.uploadId);
          ui.row.className = 'rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-2 min-w-0';
          ui.note.className = 'text-[11px] text-sage mt-1';
          ui.note.textContent = `Uploaded · ${formatBytes(file.size)}`;
          resolve();
          return;
        }

        const payload = xhr.response as { error?: string } | null;
        reject(new Error(payload?.error?.trim() || 'Upload failed.'));
      });

      xhr.addEventListener('error', () => reject(new Error('Upload failed.')));

      const formData = new FormData();
      formData.append('uploadToken', uploadToken);
      formData.append('draftShareId', draftShareId);
      formData.append('file', file, file.name);
      xhr.send(formData);
    });
  };

  const queueUploads = async (files: FileList | File[] | null | undefined): Promise<void> => {
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
        status.textContent = error instanceof Error ? error.message : 'Upload failed.';
      } finally {
        activeUploads -= 1;
        refreshState();
      }
    }
  };

  pickButton.addEventListener('click', () => {
    if (activeUploads > 0) return;
    fileInput.click();
  });

  dropzone.addEventListener('click', () => {
    if (activeUploads > 0) return;
    fileInput.click();
  });

  fileInput.addEventListener('change', () => {
    void queueUploads(fileInput.files);
    fileInput.value = '';
  });

  dropzone.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropzone.classList.add('ring-2', 'ring-terra/40');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('ring-2', 'ring-terra/40');
  });

  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('ring-2', 'ring-terra/40');
    void queueUploads(event.dataTransfer?.files || []);
  });

  restoreSenderFields();
  senderNameInput?.addEventListener('input', persistSenderFields);
  senderEmailInput?.addEventListener('input', persistSenderFields);
  senderEmailInput?.addEventListener('input', refreshState);
  senderMessageInput?.addEventListener('input', autoSizeSenderMessage);
  autoSizeSenderMessage();

  refreshState();
})();

function runConfetti(): void {
  const canvas = document.querySelector<HTMLCanvasElement>('[data-public-upload-confetti-canvas]');
  if (!canvas) return;

  const context = canvas.getContext('2d');
  if (!context) return;

  const colors = ['#C4663A', '#E8A17D', '#5B7A5E', '#1A1614', '#F0EBE3'];
  const pieceCount = 160;
  const gravity = 0.18;
  const durationMs = 4200;

  type Piece = {
    x: number;
    y: number;
    vx: number;
    vy: number;
    size: number;
    rotation: number;
    spin: number;
    color: string;
  };

  const pieces: Piece[] = [];
  let width = 0;
  let height = 0;
  let start = 0;

  const resize = (): void => {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * window.devicePixelRatio);
    canvas.height = Math.floor(height * window.devicePixelRatio);
    context.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
  };

  const resetPiece = (piece: Piece, fromTop: boolean): void => {
    piece.x = Math.random() * width;
    piece.y = fromTop ? -20 - Math.random() * height * 0.4 : Math.random() * -height;
    piece.vx = (Math.random() - 0.5) * 2.6;
    piece.vy = 2.2 + Math.random() * 2.8;
    piece.size = 5 + Math.random() * 7;
    piece.rotation = Math.random() * Math.PI * 2;
    piece.spin = (Math.random() - 0.5) * 0.25;
    piece.color = colors[Math.floor(Math.random() * colors.length)];
  };

  const init = (): void => {
    pieces.length = 0;
    for (let i = 0; i < pieceCount; i += 1) {
      const piece = {} as Piece;
      resetPiece(piece, false);
      pieces.push(piece);
    }
  };

  const draw = (): void => {
    context.clearRect(0, 0, width, height);
    for (const piece of pieces) {
      piece.x += piece.vx;
      piece.y += piece.vy;
      piece.vy += gravity * 0.02;
      piece.rotation += piece.spin;

      if (piece.y > height + 24 || piece.x < -24 || piece.x > width + 24) {
        resetPiece(piece, true);
      }

      context.save();
      context.translate(piece.x, piece.y);
      context.rotate(piece.rotation);
      context.fillStyle = piece.color;
      context.fillRect(-piece.size / 2, -piece.size / 2, piece.size, piece.size * 0.66);
      context.restore();
    }
  };

  const tick = (timestamp: number): void => {
    if (!start) start = timestamp;
    draw();
    if (timestamp - start <= durationMs) {
      requestAnimationFrame(tick);
      return;
    }

    context.clearRect(0, 0, width, height);
    canvas.remove();
  };

  resize();
  init();
  window.addEventListener('resize', resize, { passive: true });
  requestAnimationFrame(tick);
}
