"use strict";
(() => {
  // scripts/ts/share-download.ts
  (() => {
    const maxAutoRetryMs = 5 * 60 * 1e3;
    const autoRetryIntervalMs = 15 * 1e3;
    const imageRetryIntervalMs = 2500;
    const toSafeHtml = (value) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
    const attachPreviewLifecycle = (img) => {
      const statusUrl = img.dataset.previewStatusUrl || "";
      const initialPreviewUrl = img.dataset.previewUrl || img.getAttribute("src") || "";
      let retryUrl = img.dataset.previewRetryUrl || "";
      let currentPreviewUrl = initialPreviewUrl;
      if (!statusUrl || !initialPreviewUrl) return;
      const frame = img.closest(".preview-frame");
      if (!frame) return;
      if (frame.dataset.previewLifecycleAttached === "1") return;
      frame.dataset.previewLifecycleAttached = "1";
      frame.style.position = "relative";
      const placeholder = document.createElement("div");
      placeholder.className = "preview-loading-placeholder";
      placeholder.style.display = "none";
      frame.appendChild(placeholder);
      const panel = document.createElement("div");
      panel.className = "hidden";
      panel.style.position = "absolute";
      panel.style.right = "0.6rem";
      panel.style.bottom = "0.6rem";
      panel.style.display = "none";
      panel.style.gap = "0.5rem";
      panel.style.alignItems = "center";
      panel.style.background = "rgba(255,255,255,0.92)";
      panel.style.border = "1px solid #E5DFD7";
      panel.style.borderRadius = "999px";
      panel.style.padding = "0.3rem 0.45rem 0.3rem 0.6rem";
      panel.style.boxShadow = "0 2px 10px rgba(26,22,20,0.09)";
      const label = document.createElement("span");
      label.style.fontSize = "0.7rem";
      label.style.color = "#5C534A";
      label.textContent = "Preparing preview...";
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "Retry";
      button.style.border = "1px solid #E5DFD7";
      button.style.borderRadius = "999px";
      button.style.padding = "0.2rem 0.5rem";
      button.style.background = "#FAF7F2";
      button.style.color = "#1A1614";
      button.style.fontSize = "0.68rem";
      button.style.cursor = "pointer";
      panel.append(label, button);
      frame.appendChild(panel);
      let startedAt = Date.now();
      let timer = null;
      let imageRetryTimer = null;
      let active = true;
      let isRefreshing = false;
      const setPanel = (message, showRetry) => {
        label.textContent = message;
        button.style.display = showRetry ? "" : "none";
        panel.style.display = "";
      };
      const clearPanel = () => {
        panel.style.display = "none";
      };
      const showPlaceholder = () => {
        placeholder.style.display = "";
        img.style.visibility = "hidden";
      };
      const hidePlaceholder = () => {
        placeholder.style.display = "none";
        img.style.visibility = "visible";
      };
      const setImageSource = (url) => {
        currentPreviewUrl = url;
        const separator = url.includes("?") ? "&" : "?";
        img.src = `${url}${separator}v=${Date.now()}`;
      };
      const clearImageRetry = () => {
        if (imageRetryTimer) {
          window.clearTimeout(imageRetryTimer);
          imageRetryTimer = null;
        }
      };
      const probePreviewImage = async (url) => {
        const requestUrl = `${url}${url.includes("?") ? "&" : "?"}v=${Date.now()}`;
        try {
          let response = await fetch(requestUrl, {
            method: "HEAD",
            cache: "no-store",
            credentials: "same-origin"
          });
          if (response.status === 405) {
            response = await fetch(requestUrl, {
              method: "GET",
              cache: "no-store",
              credentials: "same-origin"
            });
          }
          if (response.ok) return "ready";
          if (response.status === 404) return "not_found";
          return "error";
        } catch {
          return "error";
        }
      };
      const scheduleImageRetry = () => {
        if (!active) return;
        clearImageRetry();
        imageRetryTimer = window.setTimeout(async () => {
          await refresh();
        }, imageRetryIntervalMs);
      };
      const scheduleNext = () => {
        if (!active) return;
        timer = window.setTimeout(() => void refresh(), autoRetryIntervalMs);
      };
      const refresh = async () => {
        if (!active) return;
        if (isRefreshing) return;
        isRefreshing = true;
        try {
          const response = await fetch(`${statusUrl}${statusUrl.includes("?") ? "&" : "?"}_=${Date.now()}`, {
            method: "GET",
            cache: "no-store",
            credentials: "same-origin"
          });
          if (!response.ok) {
            setPanel("Unable to check preview status.", true);
            return;
          }
          const status = await response.json();
          const state = (status.state || "").trim().toLowerCase();
          const reason = (status.reason || "").trim().toLowerCase();
          retryUrl = status.retryUrl || retryUrl;
          const nextPreviewUrl = img.dataset.previewMode === "thumbnail" ? status.thumbnailUrl || initialPreviewUrl : status.previewUrl || initialPreviewUrl;
          currentPreviewUrl = nextPreviewUrl;
          if (state === "ready") {
            const imageState = await probePreviewImage(currentPreviewUrl);
            if (imageState === "ready") {
              setImageSource(currentPreviewUrl);
              clearImageRetry();
              clearPanel();
              return;
            }
            showPlaceholder();
            setPanel("Preparing preview...", false);
            scheduleImageRetry();
            return;
          }
          if (state === "pending") {
            showPlaceholder();
            const elapsed = Date.now() - startedAt;
            if (elapsed <= maxAutoRetryMs) {
              setPanel("Preparing preview...", false);
              scheduleImageRetry();
              scheduleNext();
            } else {
              setPanel("Still preparing. You can retry now.", true);
            }
            return;
          }
          if (reason === "unsupported_type") {
            clearImageRetry();
            hidePlaceholder();
            setPanel("Preview cannot be shown for this file type.", false);
          } else {
            setPanel("Preview unavailable. Retry generation.", true);
          }
        } catch {
          setPanel("Unable to check preview status.", true);
        } finally {
          isRefreshing = false;
        }
      };
      button.addEventListener("click", async () => {
        if (!retryUrl) {
          setPanel("Retry URL unavailable.", false);
          return;
        }
        button.disabled = true;
        label.textContent = "Retry requested...";
        try {
          await fetch(`${retryUrl}${retryUrl.includes("?") ? "&" : "?"}_=${Date.now()}`, {
            method: "GET",
            cache: "no-store",
            credentials: "same-origin"
          });
          startedAt = Date.now();
          button.disabled = false;
          showPlaceholder();
          scheduleImageRetry();
          setPanel("Preparing preview...", false);
          if (timer) window.clearTimeout(timer);
          scheduleNext();
        } catch {
          button.disabled = false;
          setPanel("Retry failed. Try again.", true);
        }
      });
      img.addEventListener("load", () => {
        hidePlaceholder();
        clearImageRetry();
        clearPanel();
      });
      img.addEventListener("error", () => {
        showPlaceholder();
        setPanel("Preparing preview...", false);
        scheduleImageRetry();
      });
      showPlaceholder();
      void refresh();
    };
    document.querySelectorAll("img[data-preview-image]").forEach((img) => {
      attachPreviewLifecycle(img);
    });
    const browser = document.querySelector("[data-file-browser]");
    if (!browser) return;
    const items = Array.from(browser.querySelectorAll("[data-preview-select]"));
    const body = browser.querySelector("[data-preview-body]");
    if (!body) return;
    const renderPreviewImage = (previewImageUrl, fileName, statusUrl, retryUrl) => {
      const alt = toSafeHtml(fileName);
      const imageUrl = toSafeHtml(previewImageUrl);
      const safeStatusUrl = toSafeHtml(statusUrl);
      const safeRetryUrl = toSafeHtml(retryUrl);
      return `<div class="preview-frame"><img src="${imageUrl}" alt="${alt} preview" loading="lazy" data-preview-image data-preview-url="${imageUrl}" data-preview-status-url="${safeStatusUrl}" data-preview-retry-url="${safeRetryUrl}" data-preview-mode="full" /></div>`;
    };
    const activateItem = (item) => {
      items.forEach((node) => node.classList.remove("active"));
      item.classList.add("active");
      const previewImageUrl = item.dataset.previewImageUrl || "";
      const previewStatusUrl = item.dataset.previewStatusUrl || "";
      const previewRetryUrl = item.dataset.previewRetryUrl || "";
      const fileName = item.dataset.name || "File";
      body.innerHTML = renderPreviewImage(previewImageUrl, fileName, previewStatusUrl, previewRetryUrl);
      const nextImage = body.querySelector("img[data-preview-image]");
      if (nextImage) {
        attachPreviewLifecycle(nextImage);
      }
    };
    items.forEach((item) => {
      item.addEventListener("click", (event) => {
        const target = event.target;
        if (target?.closest(".file-icon-download")) return;
        activateItem(item);
      });
      item.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        activateItem(item);
      });
    });
  })();
})();
//# sourceMappingURL=share-download.js.map
