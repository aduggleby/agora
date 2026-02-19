"use strict";
(() => {
  // scripts/ts/lightbox.ts
  (() => {
    const box = document.getElementById("lightbox");
    const lbImg = document.getElementById("lightbox-img");
    const cap = document.getElementById("lightbox-caption");
    const dl = document.getElementById("lightbox-download");
    if (!box || !lbImg || !cap || !dl) return;
    const items = [];
    let idx = 0;
    document.querySelectorAll(".mosaic-item[data-lightbox-src]").forEach((el) => {
      items.push({
        src: el.dataset.lightboxSrc ?? "",
        name: el.dataset.lightboxName ?? "",
        download: el.dataset.lightboxDownload ?? ""
      });
    });
    const show = () => {
      if (!items.length) return;
      const it = items[idx];
      lbImg.src = it.src;
      lbImg.alt = it.name;
      cap.textContent = it.name;
      dl.href = it.download;
      box.classList.add("open");
      box.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
    };
    const close = () => {
      box.classList.remove("open");
      box.setAttribute("aria-hidden", "true");
      document.body.style.overflow = "";
    };
    const nav = (dir) => {
      idx = (idx + dir + items.length) % items.length;
      show();
    };
    window["openLightbox"] = (el) => {
      const src = el.dataset.lightboxSrc ?? "";
      idx = Math.max(0, items.findIndex((it) => it.src === src));
      show();
    };
    window["closeLightbox"] = close;
    window["navLightbox"] = nav;
    box.addEventListener("click", (e) => {
      if (e.target === box) close();
    });
    document.addEventListener("keydown", (e) => {
      if (!box.classList.contains("open")) return;
      if (e.key === "Escape") close();
      else if (e.key === "ArrowLeft") nav(-1);
      else if (e.key === "ArrowRight") nav(1);
    });
  })();
})();
//# sourceMappingURL=lightbox.js.map
