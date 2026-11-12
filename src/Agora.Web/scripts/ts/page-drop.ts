/**
 * Makes the whole page a drop target for files: dragging files anywhere over the window highlights the page's
 * dropzone and shows a full-page hint, and dropping them anywhere hands them to the same handler the dropzone
 * uses. Drags that carry no files (text, links) are left to the browser. Files dropped while the page cannot take
 * them are swallowed so the browser never navigates away to open them.
 *
 * Pasting files (Ctrl/Cmd+V) anywhere on the page hands them to the same handler, for example a screenshot copied
 * to the clipboard. A paste into a text field that also carries text stays a normal text paste.
 */
export type PageDropOptions = {
  /** The visible dropzone, highlighted while files are dragged over the page. */
  dropzone: HTMLElement;
  /** Receives the dropped files. */
  onFiles: (files: File[]) => void;
  /** Overlay text, for example "Drop files to upload". */
  label: string;
  /** Whether a drop is accepted right now (for example false while a request is running). */
  isEnabled?: () => boolean;
};

const highlightClasses = ['ring-2', 'ring-terra/40'];

const carriesFiles = (event: DragEvent): boolean => Array.from(event.dataTransfer?.types ?? []).includes('Files');

const isTextField = (target: EventTarget | null): boolean =>
  target instanceof HTMLElement &&
  (target.isContentEditable || target instanceof HTMLTextAreaElement ||
    (target instanceof HTMLInputElement && !['button', 'checkbox', 'color', 'file', 'radio', 'range', 'reset', 'submit'].includes(target.type)));

const pad = (value: number): string => String(value).padStart(2, '0');

/** Background images the landing page designers accept (the server enforces the same list). */
export const isBackgroundImage = (file: File): boolean => /\.(jpe?g|png|webp)$/i.test(file.name);

export const backgroundImageHint = 'Only .jpg, .jpeg, .png or .webp images can be used as the background.';

/** Clipboard images arrive as "image.png" (or nameless); give them a distinct, sortable name. */
export const namePastedFile = (file: File, now: Date = new Date()): File => {
  if (file.name && !/^image\.[a-z0-9]+$/i.test(file.name)) return file;
  // Nameless files take the MIME subtype without suffix or "x-" prefix: "image/svg+xml" -> "svg", "image/x-icon" -> "icon".
  const fromType = (file.type.split('/')[1] ?? '').split('+')[0].replace(/^x-/, '');
  const extension = ((file.name ? file.name.split('.').pop() : '') || fromType || 'png').toLowerCase().replace('jpeg', 'jpg');
  const stamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return new File([file], `pasted-${stamp}.${extension}`, { type: file.type, lastModified: file.lastModified });
};

const createOverlay = (label: string): HTMLDivElement => {
  const overlay = document.createElement('div');
  overlay.setAttribute('aria-hidden', 'true');
  overlay.dataset.pageDropOverlay = '';
  overlay.className = 'hidden fixed inset-0 z-50 pointer-events-none items-center justify-center bg-cream/80 p-4';

  const frame = document.createElement('div');
  frame.className = 'flex h-full w-full items-center justify-center rounded-2xl border-2 border-dashed border-terra bg-terra-wash/60';

  const text = document.createElement('p');
  text.className = 'font-display text-3xl text-terra';
  text.textContent = label;

  frame.appendChild(text);
  overlay.appendChild(frame);
  document.body.appendChild(overlay);
  return overlay;
};

export function enablePageDrop(options: PageDropOptions): void {
  const { dropzone, onFiles, label } = options;
  const isEnabled = options.isEnabled ?? (() => true);
  const overlay = createOverlay(label);
  // dragenter/dragleave fire for every element crossed; count them to know when the drag really left the window.
  let depth = 0;

  const show = (visible: boolean): void => {
    overlay.classList.toggle('hidden', !visible);
    overlay.classList.toggle('flex', visible);
    highlightClasses.forEach((name) => dropzone.classList.toggle(name, visible));
  };

  const reset = (): void => {
    depth = 0;
    show(false);
  };

  window.addEventListener('dragenter', (event) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    depth += 1;
    show(isEnabled());
  });

  window.addEventListener('dragover', (event) => {
    if (!carriesFiles(event)) return;
    // Cancelling dragover is what allows a drop; the drop effect tells the user whether it will be taken.
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = isEnabled() ? 'copy' : 'none';
  });

  window.addEventListener('dragleave', (event) => {
    if (!carriesFiles(event)) return;
    depth = Math.max(0, depth - 1);
    if (depth === 0) show(false);
  });

  window.addEventListener('drop', (event) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    reset();
    const files = Array.from(event.dataTransfer?.files ?? []);
    if (files.length > 0 && isEnabled()) onFiles(files);
  });

  window.addEventListener('dragend', reset);

  document.addEventListener('paste', (event) => {
    const clipboard = event.clipboardData;
    const files = Array.from(clipboard?.files ?? []);
    if (files.length === 0) return;
    // Office apps put a picture of the copied text next to the text: in a text field, the text wins.
    if (isTextField(event.target) && (clipboard?.types ?? []).includes('text/plain')) return;
    event.preventDefault();
    if (isEnabled()) onFiles(files.map((file) => namePastedFile(file)));
  });
}
