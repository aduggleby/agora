(() => {
  const nodes = document.querySelectorAll<HTMLElement>('[data-local-datetime]');
  if (!nodes.length) return;

  const full = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  // Compact: "Oct 14, 7:20 AM" for dense tables; the full date and time go into the tooltip.
  const compact = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });

  nodes.forEach((node) => {
    const value = node.getAttribute('data-local-datetime');
    if (!value) return;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return;
    if (node.getAttribute('data-local-datetime-style') === 'compact') {
      node.textContent = compact.format(date);
      if (!node.title) node.title = full.format(date);
      return;
    }
    node.textContent = full.format(date);
  });
})();
