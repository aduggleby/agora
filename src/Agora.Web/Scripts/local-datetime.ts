(() => {
  const nodes = document.querySelectorAll<HTMLElement>('[data-local-datetime]');
  if (!nodes.length) return;

  const formatter = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  });

  nodes.forEach((node) => {
    const value = node.getAttribute('data-local-datetime');
    if (!value) return;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return;
    node.textContent = formatter.format(date);
  });
})();
