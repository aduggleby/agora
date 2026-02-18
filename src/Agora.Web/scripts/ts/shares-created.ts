import Alpine from 'alpinejs';
import * as signalR from '@microsoft/signalr';

type CopyState = 'idle' | 'success' | 'error';

type ShareReadyCopyModel = {
  shareUrl: string;
  label: string;
  state: CopyState;
  resetTimer: number | null;
  buttonClass: string;
  fallbackCopy(value: string): boolean;
  flash(state: Exclude<CopyState, 'idle'>): void;
  copy(event: Event): Promise<void>;
};

type ShareProgressStep = {
  key?: string;
  label?: string;
  state?: string;
  detail?: string | null;
  updatedAtUtc?: string | null;
};

type ShareStatusResponse = {
  token?: string;
  state?: string;
  ready?: boolean;
  error?: string | null;
  steps?: ShareProgressStep[] | null;
};

function shareReadyCopy(shareUrl: string): ShareReadyCopyModel {
  return {
    shareUrl,
    label: 'Copy link',
    state: 'idle',
    resetTimer: null,
    get buttonClass() {
      if (this.state === 'success') return 'bg-sage hover:bg-sage';
      if (this.state === 'error') return 'bg-danger hover:bg-danger/90';
      return 'bg-terra hover:bg-terra/90';
    },
    fallbackCopy(value: string): boolean {
      const input = document.createElement('textarea');
      input.value = value;
      input.setAttribute('readonly', 'readonly');
      input.style.position = 'absolute';
      input.style.left = '-9999px';
      document.body.appendChild(input);
      input.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(input);
      return ok;
    },
    flash(state: Exclude<CopyState, 'idle'>): void {
      if (this.resetTimer) window.clearTimeout(this.resetTimer);
      this.state = state;
      this.label = state === 'success' ? 'Copied ✓' : 'Try again';
      this.resetTimer = window.setTimeout(() => {
        this.state = 'idle';
        this.label = 'Copy link';
      }, state === 'success' ? 1300 : 1200);
    },
    async copy(event: Event): Promise<void> {
      const button = event.currentTarget as HTMLElement | null;
      if (!this.shareUrl || !button) {
        this.flash('error');
        return;
      }

      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(this.shareUrl);
        } else if (!this.fallbackCopy(this.shareUrl)) {
          throw new Error('copy failed');
        }

        this.flash('success');
        button.animate(
          [{ transform: 'scale(1)' }, { transform: 'scale(1.07)' }, { transform: 'scale(1)' }],
          { duration: 260, easing: 'ease-out' }
        );
      } catch {
        this.flash('error');
        button.animate(
          [
            { transform: 'translateX(0)' },
            { transform: 'translateX(-3px)' },
            { transform: 'translateX(3px)' },
            { transform: 'translateX(0)' }
          ],
          { duration: 220, easing: 'ease-out' }
        );
      }
    }
  };
}

Object.assign(window as Window & { shareReadyCopy?: (url: string) => ShareReadyCopyModel }, {
  shareReadyCopy
});

(window as Window & { Alpine?: typeof Alpine }).Alpine = Alpine;
Alpine.start();

(() => {
  const page = document.querySelector<HTMLElement>('[data-share-created-page]');
  if (!page) return;

  const isReady = page.dataset.ready === 'true';
  if (isReady) {
    runConfetti();
    return;
  }

  const token = (page.dataset.token || '').trim();
  const hubUrl = (page.dataset.progressHubUrl || '/hubs/share-progress').trim();
  if (!token) return;

  const statusText = page.querySelector<HTMLElement>('[data-created-status-text]');
  const spinner = page.querySelector<HTMLElement>('[data-created-spinner]');
  const errorNode = page.querySelector<HTMLElement>('[data-created-error]');
  const taskList = page.querySelector<HTMLElement>('[data-created-task-list]');

  const startedAt = Date.now();
  const maxMs = 5 * 60 * 1000;
  const intervalMs = 15 * 1000;
  let timer: number | null = null;
  let stopped = false;

  const normalizeState = (value: string | undefined | null): string => (value || '').trim().toLowerCase();

  const renderTasks = (steps: ShareProgressStep[] | null | undefined): void => {
    if (!taskList) return;
    const list = Array.isArray(steps) ? steps : [];
    taskList.innerHTML = '';
    list.forEach((step) => {
      const label = (step.label || '').trim();
      if (!label) return;
      const state = normalizeState(step.state);
      const dotClass =
        state === 'completed'
          ? 'bg-sage'
          : state === 'active'
            ? 'bg-terra animate-pulse'
            : state === 'failed'
              ? 'bg-danger'
              : 'bg-ink-muted/40';
      const detail = (step.detail || '').trim();

      const item = document.createElement('li');
      item.className = 'flex items-start gap-2';
      item.innerHTML = `<span class="mt-1.5 inline-block h-2.5 w-2.5 rounded-full ${dotClass}" aria-hidden="true"></span><span class="text-sm text-ink-light">${label}${detail ? ` - ${detail}` : ''}</span>`;
      taskList.appendChild(item);
    });
  };

  const stopPolling = (): void => {
    stopped = true;
    if (timer) {
      window.clearTimeout(timer);
      timer = null;
    }
  };

  const showFailure = (message: string): void => {
    if (statusText) statusText.textContent = message;
    spinner?.setAttribute('style', 'display:none;');
    if (errorNode) {
      errorNode.textContent = message;
      errorNode.classList.remove('hidden');
    }
  };

  const applyStatusPayload = (payload: ShareStatusResponse): void => {
    renderTasks(payload.steps);
    const state = normalizeState(payload.state);

    if (payload.ready || state === 'completed') {
      stopPolling();
      window.location.reload();
      return;
    }

    if (state === 'failed') {
      stopPolling();
      showFailure(payload.error?.trim() || 'Share creation failed.');
      return;
    }

    if (statusText && !errorNode?.classList.contains('hidden')) {
      statusText.textContent = 'Preparing your link. We will email you as soon as it is ready, so you can leave this page now or wait here for automatic updates.';
      errorNode?.classList.add('hidden');
    }
  };

  const poll = async (): Promise<void> => {
    if (stopped) return;

    try {
      const response = await fetch(`/api/shares/${encodeURIComponent(token)}/status?_=${Date.now()}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin'
      });

      if (response.ok) {
        const payload = (await response.json()) as ShareStatusResponse;
        applyStatusPayload(payload);
      }
    } catch {
      // Keep polling until timeout.
    }

    if (Date.now() - startedAt >= maxMs) {
      stopPolling();
      showFailure('Still processing. Wait a moment and refresh to check again.');
      return;
    }

    timer = window.setTimeout(() => void poll(), intervalMs);
  };

  const connectSignalR = async (): Promise<void> => {
    const connection = new signalR.HubConnectionBuilder()
      .withUrl(hubUrl)
      .withAutomaticReconnect()
      .build();

    connection.on('shareStatus', (payload: ShareStatusResponse) => {
      if ((payload.token || '').trim() !== token) return;
      applyStatusPayload(payload);
    });

    try {
      await connection.start();
      await connection.invoke('JoinShare', token);
    } catch {
      // Polling remains as fallback.
    }
  };

  void connectSignalR();
  void poll();
})();

function runConfetti(): void {
  const canvas = document.querySelector<HTMLCanvasElement>('[data-confetti-canvas]');
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
