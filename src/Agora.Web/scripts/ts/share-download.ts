type PreviewStatusResponse = {
  state?: string;
  reason?: string;
  previewUrl?: string;
  thumbnailUrl?: string;
  retryUrl?: string;
};

(() => {
  const maxAutoRetryMs = 5 * 60 * 1000;
  const autoRetryIntervalMs = 15 * 1000;
  const imageRetryIntervalMs = 2500;

  const toSafeHtml = (value: string): string =>
    value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

  const attachPreviewLifecycle = (img: HTMLImageElement): void => {
    const statusUrl = img.dataset.previewStatusUrl || '';
    const initialPreviewUrl = img.dataset.previewUrl || img.getAttribute('src') || '';
    let retryUrl = img.dataset.previewRetryUrl || '';
    let currentPreviewUrl = initialPreviewUrl;
    if (!statusUrl || !initialPreviewUrl) return;

    const frame = img.closest<HTMLElement>('.preview-frame');
    if (!frame) return;
    if (frame.dataset.previewLifecycleAttached === '1') return;
    frame.dataset.previewLifecycleAttached = '1';
    frame.style.position = 'relative';

    const placeholder = document.createElement('div');
    placeholder.className = 'preview-loading-placeholder';
    placeholder.style.display = 'none';
    frame.appendChild(placeholder);

    const panel = document.createElement('div');
    panel.className = 'hidden';
    panel.style.position = 'absolute';
    panel.style.right = '0.6rem';
    panel.style.bottom = '0.6rem';
    panel.style.display = 'none';
    panel.style.gap = '0.5rem';
    panel.style.alignItems = 'center';
    panel.style.background = 'rgba(255,255,255,0.92)';
    panel.style.border = '1px solid #E5DFD7';
    panel.style.borderRadius = '999px';
    panel.style.padding = '0.3rem 0.45rem 0.3rem 0.6rem';
    panel.style.boxShadow = '0 2px 10px rgba(26,22,20,0.09)';

    const label = document.createElement('span');
    label.style.fontSize = '0.7rem';
    label.style.color = '#5C534A';
    label.textContent = 'Preparing preview...';

    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Retry';
    button.style.border = '1px solid #E5DFD7';
    button.style.borderRadius = '999px';
    button.style.padding = '0.2rem 0.5rem';
    button.style.background = '#FAF7F2';
    button.style.color = '#1A1614';
    button.style.fontSize = '0.68rem';
    button.style.cursor = 'pointer';

    panel.append(label, button);
    frame.appendChild(panel);

    let startedAt = Date.now();
    let timer: number | null = null;
    let imageRetryTimer: number | null = null;
    let active = true;

    const setPanel = (message: string, showRetry: boolean): void => {
      label.textContent = message;
      button.style.display = showRetry ? '' : 'none';
      panel.style.display = '';
    };

    const clearPanel = (): void => {
      panel.style.display = 'none';
    };

    const showPlaceholder = (): void => {
      placeholder.style.display = '';
      img.style.visibility = 'hidden';
    };

    const hidePlaceholder = (): void => {
      placeholder.style.display = 'none';
      img.style.visibility = 'visible';
    };

    const setImageSource = (url: string): void => {
      currentPreviewUrl = url;
      const separator = url.includes('?') ? '&' : '?';
      img.src = `${url}${separator}v=${Date.now()}`;
    };

    const clearImageRetry = (): void => {
      if (imageRetryTimer) {
        window.clearTimeout(imageRetryTimer);
        imageRetryTimer = null;
      }
    };

    const probePreviewImage = async (): Promise<'ready' | 'not_found' | 'error'> => {
      const requestUrl = `${currentPreviewUrl}${currentPreviewUrl.includes('?') ? '&' : '?'}v=${Date.now()}`;
      try {
        let response = await fetch(requestUrl, {
          method: 'HEAD',
          cache: 'no-store',
          credentials: 'same-origin'
        });

        if (response.status === 405) {
          response = await fetch(requestUrl, {
            method: 'GET',
            cache: 'no-store',
            credentials: 'same-origin'
          });
        }

        if (response.ok) return 'ready';
        if (response.status === 404) return 'not_found';
        return 'error';
      } catch {
        return 'error';
      }
    };

    const scheduleImageRetry = (): void => {
      if (!active) return;
      clearImageRetry();
      imageRetryTimer = window.setTimeout(async () => {
        const result = await probePreviewImage();
        if (result === 'ready') {
          setImageSource(currentPreviewUrl);
          return;
        }

        showPlaceholder();
        setPanel('Preparing preview...', false);
        scheduleImageRetry();
      }, imageRetryIntervalMs);
    };

    const scheduleNext = (): void => {
      if (!active) return;
      timer = window.setTimeout(() => void refresh(), autoRetryIntervalMs);
    };

    const refresh = async (): Promise<void> => {
      if (!active) return;

      try {
        const response = await fetch(`${statusUrl}${statusUrl.includes('?') ? '&' : '?'}_=${Date.now()}`, {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin'
        });
        if (!response.ok) {
          setPanel('Unable to check preview status.', true);
          return;
        }

        const status = (await response.json()) as PreviewStatusResponse;
        const state = (status.state || '').trim().toLowerCase();
        const reason = (status.reason || '').trim().toLowerCase();
        retryUrl = status.retryUrl || retryUrl;

        if (img.dataset.previewMode === 'thumbnail' && status.thumbnailUrl) {
          setImageSource(status.thumbnailUrl);
        } else if (status.previewUrl) {
          setImageSource(status.previewUrl);
        } else {
          setImageSource(initialPreviewUrl);
        }

        if (state === 'ready') {
          clearImageRetry();
          clearPanel();
          return;
        }

        if (state === 'pending') {
          const elapsed = Date.now() - startedAt;
          if (elapsed <= maxAutoRetryMs) {
            setPanel('Preparing preview...', false);
            scheduleNext();
          } else {
            setPanel('Still preparing. You can retry now.', true);
          }
          return;
        }

        if (reason === 'unsupported_type') {
          clearImageRetry();
          hidePlaceholder();
          setPanel('Preview cannot be shown for this file type.', false);
        } else {
          setPanel('Preview unavailable. Retry generation.', true);
        }
      } catch {
        setPanel('Unable to check preview status.', true);
      }
    };

    button.addEventListener('click', async () => {
      if (!retryUrl) {
        setPanel('Retry URL unavailable.', false);
        return;
      }

      button.disabled = true;
      label.textContent = 'Retry requested...';
      try {
        await fetch(`${retryUrl}${retryUrl.includes('?') ? '&' : '?'}_=${Date.now()}`, {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin'
        });
        startedAt = Date.now();
        button.disabled = false;
        showPlaceholder();
        scheduleImageRetry();
        setPanel('Preparing preview...', false);
        if (timer) window.clearTimeout(timer);
        scheduleNext();
      } catch {
        button.disabled = false;
        setPanel('Retry failed. Try again.', true);
      }
    });

    img.addEventListener('load', () => {
      hidePlaceholder();
      clearImageRetry();
      clearPanel();
    });

    img.addEventListener('error', () => {
      showPlaceholder();
      setPanel('Preparing preview...', false);
      scheduleImageRetry();
    });

    void refresh();
  };

  document.querySelectorAll<HTMLImageElement>('img[data-preview-image]').forEach((img) => {
    attachPreviewLifecycle(img);
  });

  const browser = document.querySelector<HTMLElement>('[data-file-browser]');
  if (!browser) return;

  const items = Array.from(browser.querySelectorAll<HTMLElement>('[data-preview-select]'));
  const body = browser.querySelector<HTMLElement>('[data-preview-body]');
  if (!body) return;

  const renderPreviewImage = (previewImageUrl: string, fileName: string, statusUrl: string, retryUrl: string): string => {
    const alt = toSafeHtml(fileName);
    const imageUrl = toSafeHtml(previewImageUrl);
    const safeStatusUrl = toSafeHtml(statusUrl);
    const safeRetryUrl = toSafeHtml(retryUrl);
    return `<div class="preview-frame"><img src="${imageUrl}" alt="${alt} preview" loading="lazy" data-preview-image data-preview-url="${imageUrl}" data-preview-status-url="${safeStatusUrl}" data-preview-retry-url="${safeRetryUrl}" data-preview-mode="full" /></div>`;
  };

  const activateItem = (item: HTMLElement): void => {
    items.forEach((node) => node.classList.remove('active'));
    item.classList.add('active');

    const previewImageUrl = item.dataset.previewImageUrl || '';
    const previewStatusUrl = item.dataset.previewStatusUrl || '';
    const previewRetryUrl = item.dataset.previewRetryUrl || '';
    const fileName = item.dataset.name || 'File';
    body.innerHTML = renderPreviewImage(previewImageUrl, fileName, previewStatusUrl, previewRetryUrl);

    const nextImage = body.querySelector<HTMLImageElement>('img[data-preview-image]');
    if (nextImage) {
      attachPreviewLifecycle(nextImage);
    }
  };

  items.forEach((item) => {
    item.addEventListener('click', (event) => {
      const target = event.target as HTMLElement | null;
      if (target?.closest('.file-icon-download')) return;
      activateItem(item);
    });

    item.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      activateItem(item);
    });
  });
})();
