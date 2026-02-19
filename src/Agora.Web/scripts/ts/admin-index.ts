(() => {
  const registrationToggle = document.querySelector<HTMLInputElement>('[data-registration-toggle]');
  registrationToggle?.addEventListener('change', () => {
    registrationToggle.form?.submit();
  });

  document.querySelectorAll<HTMLFormElement>('form[data-confirm-submit]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const message = form.getAttribute('data-confirm-submit') || 'Are you sure?';
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  const selects = document.querySelectorAll<HTMLSelectElement>('[data-user-role-select]');
  const toggles = document.querySelectorAll<HTMLButtonElement>('[data-user-enabled-toggle]');
  const toast = document.querySelector<HTMLElement>('[data-admin-toast]');
  if ((selects.length === 0 && toggles.length === 0) || !toast) return;

  const showToast = (message: string, isError: boolean): void => {
    toast.innerHTML = '';
    const node = document.createElement('div');
    node.className = `pointer-events-auto px-4 py-2 rounded-lg text-sm shadow-lg border ${
      isError
        ? 'bg-danger-wash text-danger border-danger/20'
        : 'bg-sage-wash text-sage border-sage/20'
    }`;
    node.textContent = message;
    toast.appendChild(node);
    toast.classList.remove('hidden');
    window.setTimeout(() => {
      toast.classList.add('hidden');
      toast.innerHTML = '';
    }, 2400);
  };

  const setEnabledToggleState = (button: HTMLButtonElement, isEnabled: boolean): void => {
    button.setAttribute('data-next-enabled', String(!isEnabled));
    button.textContent = isEnabled ? 'Disable' : 'Enable';
    button.classList.remove('text-ink-muted', 'hover:text-danger', 'text-sage', 'hover:underline');
    if (isEnabled) {
      button.classList.add('text-ink-muted', 'hover:text-danger');
      return;
    }
    button.classList.add('text-sage', 'hover:underline');
  };

  selects.forEach((select) => {
    select.addEventListener('change', async () => {
      const userId = select.getAttribute('data-user-id') || '';
      const previousRole = select.getAttribute('data-current-role') || '';
      const role = select.value || '';
      if (!userId || !role || role === previousRole) return;

      select.disabled = true;
      try {
        const formData = new FormData();
        formData.append('role', role);
        const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}/role`, {
          method: 'POST',
          body: formData
        });

        const payload = (await response.json().catch(() => ({}))) as { ok?: boolean; message?: string };
        if (!response.ok || !payload.ok) throw new Error(payload.message || 'Unable to update role.');

        select.setAttribute('data-current-role', role);
        showToast('Role updated.', false);
      } catch (error) {
        select.value = previousRole;
        showToast(error instanceof Error ? error.message : 'Unable to update role.', true);
      } finally {
        select.disabled = false;
      }
    });
  });

  toggles.forEach((button) => {
    button.addEventListener('click', async () => {
      const userId = button.getAttribute('data-user-id') || '';
      const nextEnabled = button.getAttribute('data-next-enabled') === 'true';
      if (!userId) return;

      button.disabled = true;
      try {
        const formData = new FormData();
        formData.append('enabled', nextEnabled ? 'true' : 'false');
        const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}/enabled`, {
          method: 'POST',
          body: formData
        });

        const payload = (await response.json().catch(() => ({}))) as { ok?: boolean; message?: string };
        if (!response.ok || !payload.ok) throw new Error(payload.message || 'Unable to update user status.');

        const row = button.closest('tr');
        const disabledBadge = row?.querySelector<HTMLElement>('[data-user-disabled-badge]');
        if (disabledBadge) {
          disabledBadge.classList.toggle('hidden', nextEnabled);
        }

        setEnabledToggleState(button, nextEnabled);
        showToast(nextEnabled ? 'User enabled.' : 'User disabled.', false);
      } catch (error) {
        showToast(error instanceof Error ? error.message : 'Unable to update user status.', true);
      } finally {
        button.disabled = false;
      }
    });
  });
})();
