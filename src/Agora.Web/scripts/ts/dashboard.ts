import { copyText } from './clipboard';

/**
 * Signed-in dashboard: tabs (My shares / Received), row and batch menus, batch selection bar, collapsible expired
 * list, upload link copy and the "received seen" marker. All state lives in the markup rendered by Index.cshtml.
 */
(() => {
  const root = document.querySelector<HTMLElement>('[data-dashboard]');
  if (!root) return;

  type TabName = 'mine' | 'received';
  const expiredStorageKey = 'agora.dashboard.expiredOpen';

  const tabs = Array.from(root.querySelectorAll<HTMLButtonElement>('[role="tab"][data-tab]'));
  const panels = Array.from(root.querySelectorAll<HTMLElement>('[data-panel]'));
  const hints = Array.from(root.querySelectorAll<HTMLElement>('[data-tab-hint]'));
  const newCount = Number(root.getAttribute('data-new-count') ?? '0') || 0;
  let seenSent = false;

  const isTabName = (value: string | null): value is TabName => value === 'mine' || value === 'received';

  const markReceivedSeen = (): void => {
    if (seenSent || newCount <= 0) return;
    seenSent = true;
    // This script runs before csrf-client.js patches fetch, so send the CSRF header explicitly.
    const csrf = document.cookie
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith('agora.csrf.request='))
      ?.slice('agora.csrf.request='.length);
    const headers: Record<string, string> = csrf ? { 'X-CSRF-TOKEN': decodeURIComponent(csrf) } : {};
    // Marks everything up to the newest received share shown on this page as seen.
    const seenUpTo = root.getAttribute('data-seen-up-to');
    if (!seenUpTo) return;
    const query = `?seenUpTo=${encodeURIComponent(seenUpTo)}`;
    // The badge and "New" markers stay for this page view; the next load no longer shows them.
    void fetch(`/account/received-seen${query}`, { method: 'POST', credentials: 'same-origin', headers })
      .then((response) => {
        if (!response.ok) seenSent = false;
      })
      .catch(() => {
        seenSent = false;
      });
  };

  const selectTab = (name: TabName, focus = false): void => {
    tabs.forEach((tab) => {
      const on = tab.dataset.tab === name;
      tab.setAttribute('aria-selected', on ? 'true' : 'false');
      tab.tabIndex = on ? 0 : -1;
      const active = (tab.dataset.activeClass ?? '').split(' ').filter(Boolean);
      const idle = (tab.dataset.idleClass ?? '').split(' ').filter(Boolean);
      tab.classList.remove(...active, ...idle);
      tab.classList.add(...(on ? active : idle));
      if (on && focus) tab.focus();
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.panel !== name;
    });
    hints.forEach((hint) => {
      hint.hidden = hint.dataset.tabHint !== name;
    });
    const url = new URL(window.location.href);
    url.searchParams.delete('msg');
    if (name === 'received') url.searchParams.set('tab', 'received');
    else url.searchParams.delete('tab');
    window.history.replaceState(null, '', url.pathname + url.search + url.hash);
    if (name === 'received') markReceivedSeen();
  };

  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => {
      if (isTabName(tab.dataset.tab ?? null)) selectTab(tab.dataset.tab as TabName);
    });
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault();
      const next = tabs[(index + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      if (next && isTabName(next.dataset.tab ?? null)) selectTab(next.dataset.tab as TabName, true);
    });
  });

  // ---- menus (row "..." and batch actions) ----
  const closeMenu = (menuRoot: HTMLElement): void => {
    const list = menuRoot.querySelector<HTMLElement>('[data-menu-list]');
    if (list) list.hidden = true;
    menuRoot.querySelector<HTMLElement>('[data-menu-button]')?.setAttribute('aria-expanded', 'false');
  };

  const closeMenus = (except?: HTMLElement | null): void => {
    root.querySelectorAll<HTMLElement>('[data-menu-root]').forEach((menuRoot) => {
      if (menuRoot !== except) closeMenu(menuRoot);
    });
  };

  const placeMenu = (list: HTMLElement, button: HTMLElement): void => {
    // Open upward when the list would run past the bottom of the viewport.
    const needed = list.offsetHeight + 8;
    const flip = button.getBoundingClientRect().bottom + needed > window.innerHeight && button.getBoundingClientRect().top > needed;
    list.classList.toggle('bottom-full', flip);
    list.classList.toggle('mb-1', flip);
    list.classList.toggle('top-full', !flip);
    list.classList.toggle('mt-1', !flip);
  };

  root.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null;
    if (target?.closest('[data-menu-list] a, [data-menu-list] button')) closeMenus();
    const button = target?.closest<HTMLElement>('[data-menu-button]');
    if (!button) return;
    const menuRoot = button.closest<HTMLElement>('[data-menu-root]');
    const list = menuRoot?.querySelector<HTMLElement>('[data-menu-list]');
    if (!menuRoot || !list) return;
    closeMenus(menuRoot);
    list.hidden = !list.hidden;
    button.setAttribute('aria-expanded', list.hidden ? 'false' : 'true');
    if (!list.hidden) placeMenu(list, button);
  });

  document.addEventListener('click', (event) => {
    const target = event.target as Node | null;
    root.querySelectorAll<HTMLElement>('[data-menu-root]').forEach((menuRoot) => {
      if (!target || !menuRoot.contains(target)) closeMenu(menuRoot);
    });
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    const open = root.querySelector<HTMLElement>('[data-menu-list]:not([hidden])');
    if (!open) return;
    const button = open.closest<HTMLElement>('[data-menu-root]')?.querySelector<HTMLElement>('[data-menu-button]');
    closeMenus();
    button?.focus();
  });

  // ---- batch selection ----
  type Batch = { scope: string; bar: HTMLFormElement; clear: HTMLElement | null; count: HTMLElement | null; reenable: HTMLButtonElement | null; del: HTMLElement | null };
  const batches: Batch[] = Array.from(root.querySelectorAll<HTMLFormElement>('[data-batch-bar]')).map((bar) => ({
    scope: bar.dataset.batchBar ?? '',
    bar,
    clear: bar.querySelector<HTMLElement>('[data-batch-clear]'),
    count: bar.querySelector<HTMLElement>('[data-batch-count]'),
    reenable: bar.querySelector<HTMLButtonElement>('[data-batch-reenable]'),
    del: bar.querySelector<HTMLElement>('[data-batch-delete]')
  }));

  const selectedFor = (batch: Batch): HTMLInputElement[] =>
    Array.from(root.querySelectorAll<HTMLInputElement>(`input[data-row-select][form="batch-${batch.scope}"]`)).filter((box) => box.checked);

  const updateBatch = (batch: Batch): void => {
    const selected = selectedFor(batch);
    batch.bar.hidden = selected.length === 0;
    if (selected.length === 0) closeMenus();
    if (batch.count) batch.count.textContent = String(selected.length);
    if (batch.reenable) {
      const ok = selected.some((box) => box.dataset.expired === 'true' && box.dataset.direct !== 'true');
      batch.reenable.disabled = !ok;
      batch.reenable.title = ok
        ? 'Re-enables the selected expired shares for 24 hours'
        : 'Select an expired share (direct links cannot be re-enabled)';
    }
  };

  const batchOf = (box: HTMLInputElement): Batch | undefined => batches.find((batch) => box.getAttribute('form') === `batch-${batch.scope}`);

  root.addEventListener('change', (event) => {
    const target = event.target as HTMLInputElement | null;
    if (!target?.matches('input[data-row-select]')) return;
    const batch = batchOf(target);
    if (batch) updateBatch(batch);
  });

  // Dialogs opened from a menu give focus back to that menu's button when they close (cancel or Escape).
  let returnFocus: HTMLElement | null = null;
  const rememberTrigger = (from: Element | null): void => {
    returnFocus = from?.closest<HTMLElement>('[data-menu-root]')?.querySelector<HTMLElement>('[data-menu-button]') ?? null;
  };
  root.addEventListener(
    'click',
    (event) => {
      const trigger = (event.target as HTMLElement | null)?.closest('[data-share-delete-trigger]');
      if (trigger) rememberTrigger(trigger);
    },
    true
  );
  document.querySelectorAll<HTMLDialogElement>('[data-share-delete-dialog], [data-batch-delete-dialog]').forEach((dialog) => {
    dialog.addEventListener('close', () => returnFocus?.focus());
  });

  const batchDialog = document.querySelector<HTMLDialogElement>('[data-batch-delete-dialog]');
  let pendingBatch: Batch | null = null;

  batches.forEach((batch) => {
    batch.clear?.addEventListener('click', () => {
      root.querySelectorAll<HTMLInputElement>(`input[data-row-select][form="batch-${batch.scope}"]`).forEach((box) => {
        box.checked = false;
      });
      updateBatch(batch);
    });
    batch.del?.addEventListener('click', () => {
      rememberTrigger(batch.del);
      closeMenus();
      pendingBatch = batch;
      const summary = batchDialog?.querySelector<HTMLElement>('[data-batch-delete-summary]');
      if (summary) summary.textContent = `${selectedFor(batch).length} share(s) selected.`;
      batchDialog?.showModal();
    });
    updateBatch(batch);
  });

  batchDialog?.querySelector<HTMLElement>('[data-batch-delete-cancel]')?.addEventListener('click', () => batchDialog.close());
  batchDialog?.querySelector<HTMLElement>('[data-batch-delete-confirm]')?.addEventListener('click', () => {
    const batch = pendingBatch;
    batchDialog.close();
    if (!batch) return;
    batch.bar.action = '/shares/delete-batch';
    batch.bar.submit();
  });

  // ---- expired section ----
  const toggle = root.querySelector<HTMLButtonElement>('[data-expired-toggle]');
  const expiredList = root.querySelector<HTMLElement>('[data-expired-list]');
  if (toggle && expiredList) {
    const label = toggle.querySelector<HTMLElement>('[data-expired-label]');
    const arrow = toggle.querySelector<HTMLElement>('[data-expired-arrow]');
    const count = toggle.dataset.expiredCount ?? '0';

    const setOpen = (open: boolean, persist: boolean): void => {
      expiredList.hidden = !open;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (label) label.textContent = `${open ? 'Hide' : 'Show'} expired (${count})`;
      if (arrow) arrow.style.transform = open ? 'rotate(90deg)' : '';
      if (!open) {
        // Rows that are no longer visible must not stay selected.
        expiredList.querySelectorAll<HTMLInputElement>('input[data-row-select]:checked').forEach((box) => {
          box.checked = false;
          const batch = batchOf(box);
          if (batch) updateBatch(batch);
        });
      }
      if (!persist) return;
      try {
        window.localStorage.setItem(expiredStorageKey, open ? '1' : '0');
      } catch {
        // Storage can be unavailable (private windows, blocked site data); the toggle still works.
      }
    };

    let stored = false;
    try {
      stored = window.localStorage.getItem(expiredStorageKey) === '1';
    } catch {
      stored = false;
    }
    setOpen(stored, false);
    toggle.addEventListener('click', () => setOpen(expiredList.hidden, true));
  }

  // ---- upload link copy ----
  const copyButton = root.querySelector<HTMLButtonElement>('[data-copy-upload-link]');
  const linkNode = root.querySelector<HTMLElement>('[data-upload-link]');
  if (copyButton && linkNode) {
    let timer: number | undefined;
    copyButton.addEventListener('click', async () => {
      const ok = await copyText(linkNode.textContent?.trim() ?? '');
      copyButton.textContent = ok ? 'Copied' : 'Copy failed';
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        copyButton.textContent = 'Copy';
      }, 2000);
    });
  }

  if (tabs.some((tab) => tab.dataset.tab === 'received' && tab.getAttribute('aria-selected') === 'true')) {
    markReceivedSeen();
  }
})();
