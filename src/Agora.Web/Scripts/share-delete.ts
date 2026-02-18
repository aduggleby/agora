(() => {
  const dialog = document.querySelector<HTMLDialogElement>('[data-share-delete-dialog]');
  if (!dialog) return;

  const nameNode = dialog.querySelector<HTMLElement>('[data-share-delete-name]');
  const cancelButton = dialog.querySelector<HTMLButtonElement>('[data-share-delete-cancel]');
  const confirmButton = dialog.querySelector<HTMLButtonElement>('[data-share-delete-confirm]');
  let pendingForm: HTMLFormElement | null = null;

  document.querySelectorAll<HTMLElement>('[data-share-delete-trigger]').forEach((button) => {
    button.addEventListener('click', () => {
      const form = button.closest<HTMLFormElement>('[data-share-delete-form]');
      if (!form) return;
      pendingForm = form;
      if (nameNode) {
        nameNode.textContent = form.getAttribute('data-share-name') || '';
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
