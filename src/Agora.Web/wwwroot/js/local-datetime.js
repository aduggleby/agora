"use strict";
(() => {
  // scripts/ts/local-datetime.ts
  (() => {
    const nodes = document.querySelectorAll("[data-local-datetime]");
    if (!nodes.length) return;
    const full = new Intl.DateTimeFormat(void 0, { dateStyle: "medium", timeStyle: "short" });
    const compact = new Intl.DateTimeFormat(void 0, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    nodes.forEach((node) => {
      const value = node.getAttribute("data-local-datetime");
      if (!value) return;
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return;
      if (node.getAttribute("data-local-datetime-style") === "compact") {
        node.textContent = compact.format(date);
        if (!node.title) node.title = full.format(date);
        return;
      }
      node.textContent = full.format(date);
    });
  })();
})();
//# sourceMappingURL=local-datetime.js.map
