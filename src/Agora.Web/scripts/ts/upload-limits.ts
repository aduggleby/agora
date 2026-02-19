export type UploadLimits = {
  maxFilesPerShare: number;
  maxFileSizeBytes: number;
  maxTotalUploadBytes: number;
};

export const formatLimitBytes = (bytes: number): string => {
  if (!Number.isFinite(bytes) || bytes <= 0) return '';
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
};

export type ValidationResult = { ok: true } | { ok: false; message: string };

/**
 * Validate a batch of files against upload limits before any upload starts.
 * `currentFileCount` = already-uploaded + in-flight files.
 * `currentTotalBytes` = sum of already-uploaded file sizes.
 */
export const validateFileSelection = (
  files: File[],
  limits: UploadLimits,
  currentFileCount: number,
  currentTotalBytes: number
): ValidationResult => {
  if (files.length === 0) return { ok: true };

  if (limits.maxFilesPerShare > 0 && currentFileCount >= limits.maxFilesPerShare) {
    return { ok: false, message: `You already have ${currentFileCount} file(s) staged — the maximum is ${limits.maxFilesPerShare} files per share.` };
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

let limitDialog: HTMLDialogElement | null = null;
let limitDialogMessage: HTMLParagraphElement | null = null;

const ensureDialog = (): { dialog: HTMLDialogElement; messageNode: HTMLParagraphElement } => {
  if (limitDialog && limitDialogMessage) return { dialog: limitDialog, messageNode: limitDialogMessage };

  const dialog = document.createElement('dialog');
  dialog.className = 'rounded-xl border border-border bg-white p-0 w-full max-w-sm m-auto';
  dialog.style.cssText = 'margin: auto;';
  dialog.setAttribute('style', 'margin: auto; --tw-shadow: 0 10px 15px -3px rgb(0 0 0 / .1); box-shadow: var(--tw-shadow);');

  const inner = document.createElement('div');
  inner.className = 'p-5';

  const heading = document.createElement('h3');
  heading.className = 'font-display text-2xl tracking-tight';
  heading.textContent = 'Upload limit reached';

  const message = document.createElement('p');
  message.className = 'text-sm text-ink-muted mt-2';

  const footer = document.createElement('div');
  footer.className = 'mt-5 flex justify-end';

  const okButton = document.createElement('button');
  okButton.type = 'button';
  okButton.className = 'px-4 py-2 text-sm bg-terra text-white rounded-lg hover:bg-terra/90 transition-colors';
  okButton.textContent = 'OK';
  okButton.addEventListener('click', () => dialog.close());

  footer.appendChild(okButton);
  inner.append(heading, message, footer);
  dialog.appendChild(inner);

  // Also close on backdrop click
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });

  document.body.appendChild(dialog);
  limitDialog = dialog;
  limitDialogMessage = message;

  return { dialog, messageNode: message };
};

/** Show a modal dialog with the validation error message. */
export const showLimitDialog = (message: string): void => {
  const { dialog, messageNode } = ensureDialog();
  messageNode.textContent = message;
  dialog.showModal();
};

/** Read limits from a container element's data attributes. */
export const readLimitsFromElement = (el: HTMLElement): UploadLimits => ({
  maxFilesPerShare: Number(el.dataset.maxFilesPerShare || '0'),
  maxFileSizeBytes: Number(el.dataset.maxFileSizeBytes || '0'),
  maxTotalUploadBytes: Number(el.dataset.maxTotalUploadBytes || '0')
});
