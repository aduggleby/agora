(() => {
  const form = document.getElementById('share-template-form') as HTMLFormElement | null;
  if (!form) return;

  const titleInput = form.querySelector<HTMLInputElement>('[data-template-title]');
  const h1Input = form.querySelector<HTMLInputElement>('[data-template-h1]');
  const descriptionInput = form.querySelector<HTMLTextAreaElement>('[data-template-description]');
  const backgroundFileInput = form.querySelector<HTMLInputElement>('[data-template-background-file]');
  const backgroundUploadIdInput = form.querySelector<HTMLInputElement>('[data-template-background-upload-id]');
  const backgroundColorHexInput = form.querySelector<HTMLInputElement>('[data-template-background-color-hex]');
  const backgroundColorModeInput = form.querySelector<HTMLSelectElement>('[data-template-background-color-mode]');
  const backgroundColorInput = form.querySelector<HTMLInputElement>('[data-template-background-color]');
  const backgroundColorWrap = form.querySelector<HTMLElement>('[data-template-background-color-picker-wrap]');
  const draftShareIdInput = form.querySelector<HTMLInputElement>('[data-draft-share-id]');
  const uploadDropzone = form.querySelector<HTMLElement>('[data-template-upload-dropzone]');
  const uploadPick = form.querySelector<HTMLButtonElement>('[data-template-upload-pick]');
  const uploadStatus = form.querySelector<HTMLElement>('[data-template-upload-status]');
  const previewTitle = document.querySelector<HTMLElement>('[data-preview-title]');
  const previewH1 = document.querySelector<HTMLElement>('[data-preview-h1]');
  const previewDescription = document.querySelector<HTMLElement>('[data-preview-description]');
  const previewCard = document.querySelector<HTMLElement>('[data-preview-card]');

  if (
    !titleInput ||
    !h1Input ||
    !descriptionInput ||
    !backgroundFileInput ||
    !backgroundUploadIdInput ||
    !uploadDropzone ||
    !uploadPick ||
    !uploadStatus ||
    !previewTitle ||
    !previewH1 ||
    !previewDescription ||
    !previewCard
  ) {
    return;
  }

  const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.svg', '.webp']);
  let uploadedPreviewUrl = '';

  const updatePreview = (): void => {
    previewTitle.textContent = titleInput.value || 'Shared file';
    previewH1.textContent = h1Input.value || 'A file was shared with you';
    previewDescription.textContent = descriptionInput.value || '';

    const customBackgroundColor =
      backgroundColorModeInput && backgroundColorInput && backgroundColorModeInput.value === 'custom'
        ? backgroundColorInput.value
        : '';

    previewCard.style.backgroundColor = customBackgroundColor || '';
    previewCard.style.backgroundImage = uploadedPreviewUrl ? `url(${uploadedPreviewUrl})` : '';
  };

  const setStatus = (text: string, isError: boolean): void => {
    uploadStatus.textContent = text;
    uploadStatus.classList.remove('text-ink-muted', 'text-danger');
    uploadStatus.classList.add(isError ? 'text-danger' : 'text-ink-muted');
  };

  const stageBackground = (file: File): void => {
    setStatus('Uploading background image...', false);

    const formData = new FormData();
    formData.append('file', file, file.name);
    if (draftShareIdInput?.value) {
      formData.append('draftShareId', draftShareIdInput.value);
    }

    fetch('/api/uploads/stage-template-background', { method: 'POST', body: formData })
      .then((response) => (response.ok ? response.json() : Promise.reject(new Error('Upload failed'))))
      .then((json: { uploadId?: string; fileName?: string }) => {
        const backgroundUploadId = json.uploadId || '';
        backgroundUploadIdInput.value = backgroundUploadId;

        if (uploadedPreviewUrl) URL.revokeObjectURL(uploadedPreviewUrl);
        uploadedPreviewUrl = URL.createObjectURL(file);

        setStatus(backgroundUploadId ? `Uploaded: ${json.fileName || file.name}` : 'Upload failed.', !backgroundUploadId);
        updatePreview();
      })
      .catch(() => {
        setStatus('Upload failed.', true);
      });
  };

  const handleSelectedFiles = (files: FileList | File[]): void => {
    const list = Array.from(files || []);
    if (!list.length) return;
    if (list.length > 1) {
      setStatus('Only one image can be selected.', true);
      return;
    }

    const file = list[0];
    const ext = file.name.includes('.') ? file.name.toLowerCase().slice(file.name.lastIndexOf('.')) : '';
    if (!allowedExtensions.has(ext)) {
      setStatus('Only JPG, PNG, SVG, or WEBP files are allowed.', true);
      return;
    }

    stageBackground(file);
  };

  [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener('input', updatePreview));

  if (backgroundColorModeInput && backgroundColorInput && backgroundColorHexInput) {
    const refreshColorMode = (): void => {
      const isCustom = backgroundColorModeInput.value === 'custom';
      backgroundColorWrap?.classList.toggle('hidden', !isCustom);
      backgroundColorHexInput.value = isCustom ? backgroundColorInput.value : '';
      updatePreview();
    };

    backgroundColorModeInput.addEventListener('change', refreshColorMode);
    backgroundColorInput.addEventListener('input', refreshColorMode);
    refreshColorMode();
  }

  uploadPick.addEventListener('click', () => backgroundFileInput.click());
  backgroundFileInput.addEventListener('change', () => handleSelectedFiles(backgroundFileInput.files || []));

  uploadDropzone.addEventListener('dragover', (event) => {
    event.preventDefault();
    uploadDropzone.classList.add('ring-2', 'ring-terra/40');
  });
  uploadDropzone.addEventListener('dragleave', () => uploadDropzone.classList.remove('ring-2', 'ring-terra/40'));
  uploadDropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    uploadDropzone.classList.remove('ring-2', 'ring-terra/40');
    handleSelectedFiles(event.dataTransfer?.files || []);
  });

  if (backgroundUploadIdInput.value) {
    setStatus('Uploaded background image selected.', false);
  }

  updatePreview();
})();
