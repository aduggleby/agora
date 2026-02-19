type LightboxItem = {
  src: string;
  name: string;
  download: string;
};

(() => {
  // Lightbox
  const box = document.getElementById('lightbox');
  const lbImg = document.getElementById('lightbox-img') as HTMLImageElement | null;
  const cap = document.getElementById('lightbox-caption');
  const dl = document.getElementById('lightbox-download') as HTMLAnchorElement | null;

  if (!box || !lbImg || !cap || !dl) return;

  const items: LightboxItem[] = [];
  let idx = 0;

  document.querySelectorAll<HTMLElement>('.mosaic-item[data-lightbox-src]').forEach((el) => {
    items.push({
      src: el.dataset.lightboxSrc ?? '',
      name: el.dataset.lightboxName ?? '',
      download: el.dataset.lightboxDownload ?? '',
    });
  });

  const show = (): void => {
    if (!items.length) return;
    const it = items[idx];
    lbImg.src = it.src;
    lbImg.alt = it.name;
    cap.textContent = it.name;
    dl.href = it.download;
    box.classList.add('open');
    box.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  };

  const close = (): void => {
    box.classList.remove('open');
    box.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  };

  const nav = (dir: number): void => {
    idx = (idx + dir + items.length) % items.length;
    show();
  };

  // Expose for inline onclick handlers
  (window as Record<string, unknown>)['openLightbox'] = (el: HTMLElement): void => {
    const src = el.dataset.lightboxSrc ?? '';
    idx = Math.max(0, items.findIndex((it) => it.src === src));
    show();
  };
  (window as Record<string, unknown>)['closeLightbox'] = close;
  (window as Record<string, unknown>)['navLightbox'] = nav;

  box.addEventListener('click', (e) => {
    if (e.target === box) close();
  });

  document.addEventListener('keydown', (e) => {
    if (!box.classList.contains('open')) return;
    if (e.key === 'Escape') close();
    else if (e.key === 'ArrowLeft') nav(-1);
    else if (e.key === 'ArrowRight') nav(1);
  });
})();
