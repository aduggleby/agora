"use strict";
(() => {
  // Scripts/local-datetime.ts
  (() => {
    const nodes = document.querySelectorAll("[data-local-datetime]");
    if (!nodes.length) return;
    const formatter = new Intl.DateTimeFormat(void 0, {
      dateStyle: "medium",
      timeStyle: "short"
    });
    nodes.forEach((node) => {
      const value = node.getAttribute("data-local-datetime");
      if (!value) return;
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return;
      node.textContent = formatter.format(date);
    });
  })();
})();
//# sourceMappingURL=local-datetime.js.map
