(() => {
  const form = document.getElementById('account-template-form') as HTMLFormElement | null;
  if (!form) return;

  const currentScript = document.currentScript as HTMLScriptElement | null;
  const initialBackgroundUrl = currentScript?.dataset.initialBackgroundUrl || '';

  const titleInput = form.querySelector<HTMLInputElement>('[data-preview-title]');
  const h1Input = form.querySelector<HTMLInputElement>('[data-preview-h1]');
  const descriptionInput = form.querySelector<HTMLTextAreaElement>('[data-preview-description]');
  const backgroundFileInput = form.querySelector<HTMLInputElement>('[data-preview-background-file]');
  const backgroundColorModeInput = form.querySelector<HTMLSelectElement>('[data-preview-background-color-mode]');
  const backgroundColorInput = form.querySelector<HTMLInputElement>('[data-preview-background-color]');
  const containerPositionInput = form.querySelector<HTMLSelectElement>('[data-preview-container-position]');
  const backgroundColorWrap = form.querySelector<HTMLElement>('[data-preview-background-color-picker-wrap]');
  const uploadPick = form.querySelector<HTMLButtonElement>('[data-preview-upload-pick]');
  const uploadDropzone = form.querySelector<HTMLElement>('[data-preview-upload-dropzone]');
  const uploadStatus = form.querySelector<HTMLElement>('[data-preview-upload-status]');

  const subtitleTarget = document.querySelector<HTMLElement>('[data-share-preview-subtitle]');
  const h1Target = document.querySelector<HTMLElement>('[data-share-preview-h1]');
  const descriptionTarget = document.querySelector<HTMLElement>('[data-share-preview-description]');
  const previewSurface = document.querySelector<HTMLElement>('[data-preview-surface]');
  const previewWrapper = document.querySelector<HTMLElement>('[data-preview-wrapper]');

  if (
    !titleInput ||
    !h1Input ||
    !descriptionInput ||
    !backgroundFileInput ||
    !backgroundColorModeInput ||
    !backgroundColorInput ||
    !containerPositionInput ||
    !backgroundColorWrap ||
    !uploadPick ||
    !uploadDropzone ||
    !uploadStatus
  ) {
    return;
  }

  const defaultBackgroundColor = '#faf7f2';
  let uploadedPreviewUrl = initialBackgroundUrl;

  const allPositionClasses = [
    'items-start',
    'items-center',
    'items-end',
    'justify-start',
    'justify-center',
    'justify-end'
  ];

  const positionClassMap: Record<string, string[]> = {
    top_left: ['items-start', 'justify-start'],
    top_right: ['items-start', 'justify-end'],
    bottom_left: ['items-end', 'justify-start'],
    bottom_right: ['items-end', 'justify-end'],
    center_right: ['items-center', 'justify-end'],
    center_left: ['items-center', 'justify-start'],
    center_top: ['items-start', 'justify-center'],
    center_bottom: ['items-end', 'justify-center'],
    center: ['items-center', 'justify-center']
  };

  const update = (): void => {
    if (subtitleTarget) {
      const subtitleText = titleInput.value || '';
      subtitleTarget.textContent = subtitleText;
      subtitleTarget.style.display = subtitleText ? '' : 'none';
    }

    if (h1Target) h1Target.textContent = h1Input.value || 'A file was shared with you';
    if (descriptionTarget) descriptionTarget.textContent = descriptionInput.value || '';

    if (previewSurface) {
      previewSurface.style.backgroundColor = backgroundColorModeInput.value === 'custom' ? backgroundColorInput.value : defaultBackgroundColor;
      previewSurface.style.backgroundImage = uploadedPreviewUrl ? `url(${uploadedPreviewUrl})` : '';
      previewSurface.style.backgroundSize = uploadedPreviewUrl ? 'cover' : '';
      previewSurface.style.backgroundPosition = uploadedPreviewUrl ? 'center' : '';
    }

    if (previewWrapper) {
      previewWrapper.classList.remove(...allPositionClasses);
      const next = positionClassMap[containerPositionInput.value] || positionClassMap.center;
      previewWrapper.classList.add(...next);
    }
  };

  const refreshColorMode = (): void => {
    const isCustom = backgroundColorModeInput.value === 'custom';
    backgroundColorWrap.classList.toggle('hidden', !isCustom);
    backgroundColorInput.name = isCustom ? 'backgroundColorHex' : '';
    if (!isCustom) backgroundColorInput.value = '#faf7f2';
    update();
  };

  const applyFile = (file: File): void => {
    if (uploadedPreviewUrl && uploadedPreviewUrl.startsWith('blob:')) {
      URL.revokeObjectURL(uploadedPreviewUrl);
    }
    uploadedPreviewUrl = URL.createObjectURL(file);
    uploadStatus.textContent = `Selected: ${file.name}`;
    update();
  };

  [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener('input', update));
  backgroundColorModeInput.addEventListener('change', refreshColorMode);
  backgroundColorInput.addEventListener('input', update);
  containerPositionInput.addEventListener('change', update);

  uploadPick.addEventListener('click', () => backgroundFileInput.click());
  backgroundFileInput.addEventListener('change', () => {
    const file = backgroundFileInput.files?.[0];
    if (file) applyFile(file);
  });

  uploadDropzone.addEventListener('dragover', (event) => {
    event.preventDefault();
    uploadDropzone.classList.add('ring-2', 'ring-terra/40');
  });
  uploadDropzone.addEventListener('dragleave', () => uploadDropzone.classList.remove('ring-2', 'ring-terra/40'));
  uploadDropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    uploadDropzone.classList.remove('ring-2', 'ring-terra/40');
    const file = event.dataTransfer?.files?.[0];
    if (file) applyFile(file);
  });

  refreshColorMode();
  if (initialBackgroundUrl) {
    uploadStatus.textContent = 'Uploaded background image selected.';
  }
})();
