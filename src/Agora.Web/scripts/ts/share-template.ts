(() => {
  const form = document.querySelector<HTMLFormElement>('[data-share-form]');
  if (!form) return;

  const summary = form.querySelector<HTMLElement>('[data-template-summary]');
  const modeInput = form.querySelector<HTMLSelectElement>('[data-template-mode]');
  const titleInput = form.querySelector<HTMLInputElement>('[data-template-title]');
  const h1Input = form.querySelector<HTMLInputElement>('[data-template-h1]');
  const customActions = form.querySelector<HTMLElement>('[data-template-custom-actions]');
  const designerLink = form.querySelector<HTMLAnchorElement>('[data-template-designer-link]');
  if (!modeInput) return;

  const refreshSummary = (): void => {
    if (modeInput.value !== 'per_upload') {
      if (summary) summary.textContent = 'Using account default template.';
      customActions?.classList.add('hidden');
      return;
    }

    const heading = h1Input?.value || titleInput?.value || 'Untitled';
    if (summary) summary.textContent = `Custom design selected: ${heading}.`;
    customActions?.classList.remove('hidden');
  };

  designerLink?.addEventListener('click', (event) => {
    if (modeInput.value !== 'per_upload') {
      event.preventDefault();
    }
  });

  modeInput.addEventListener('change', refreshSummary);
  refreshSummary();
})();
