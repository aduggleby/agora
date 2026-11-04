// Settings > Connected apps: Revoke asks for confirmation in a dialog before its form posts.
(() => {
  const dialog = document.querySelector<HTMLDialogElement>('[data-revoke-app-dialog]');
  if (!dialog) return;

  const nameNode = dialog.querySelector<HTMLElement>('[data-revoke-app-name]');
  const cancelButton = dialog.querySelector<HTMLButtonElement>('[data-revoke-app-cancel]');
  const confirmButton = dialog.querySelector<HTMLButtonElement>('[data-revoke-app-confirm]');
  let pendingForm: HTMLFormElement | null = null;

  document.querySelectorAll<HTMLButtonElement>('[data-revoke-app-trigger]').forEach((button) => {
    button.addEventListener('click', () => {
      const form = button.closest<HTMLFormElement>('[data-revoke-app-form]');
      if (!form) return;
      pendingForm = form;
      if (nameNode) {
        nameNode.textContent = form.getAttribute('data-app-name') || '';
      }
      dialog.showModal();
    });
  });

  cancelButton?.addEventListener('click', () => dialog.close());
  confirmButton?.addEventListener('click', () => {
    pendingForm?.submit();
    dialog.close();
  });
})();
