"use strict";
(() => {
  // scripts/ts/upload-limits.ts
  var formatLimitBytes = (bytes) => {
    if (!Number.isFinite(bytes) || bytes <= 0) return "";
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };
  var validateFileSelection = (files, limits, currentFileCount, currentTotalBytes) => {
    if (files.length === 0) return { ok: true };
    if (limits.maxFilesPerShare > 0 && currentFileCount >= limits.maxFilesPerShare) {
      return { ok: false, message: `You already have ${currentFileCount} file(s) staged \u2014 the maximum is ${limits.maxFilesPerShare} files per share.` };
    }
    if (limits.maxFilesPerShare > 0 && currentFileCount + files.length > limits.maxFilesPerShare) {
      const remaining = limits.maxFilesPerShare - currentFileCount;
      return {
        ok: false,
        message: `You selected ${files.length} file(s) but can only add ${remaining} more (limit: ${limits.maxFilesPerShare} per share).`
      };
    }
    let batchBytes = 0;
    for (const file of files) {
      if (limits.maxFileSizeBytes > 0 && file.size > limits.maxFileSizeBytes) {
        return {
          ok: false,
          message: `"${file.name}" is ${formatLimitBytes(file.size)} which exceeds the per-file limit of ${formatLimitBytes(limits.maxFileSizeBytes)}.`
        };
      }
      batchBytes += file.size;
      if (limits.maxTotalUploadBytes > 0 && currentTotalBytes + batchBytes > limits.maxTotalUploadBytes) {
        return {
          ok: false,
          message: `Adding these files would exceed the total upload limit of ${formatLimitBytes(limits.maxTotalUploadBytes)}.`
        };
      }
    }
    return { ok: true };
  };
  var limitDialog = null;
  var limitDialogMessage = null;
  var ensureDialog = () => {
    if (limitDialog && limitDialogMessage) return { dialog: limitDialog, messageNode: limitDialogMessage };
    const dialog = document.createElement("dialog");
    dialog.className = "rounded-xl border border-border bg-white p-0 w-full max-w-sm m-auto";
    dialog.style.cssText = "margin: auto;";
    dialog.setAttribute("style", "margin: auto; --tw-shadow: 0 10px 15px -3px rgb(0 0 0 / .1); box-shadow: var(--tw-shadow);");
    const inner = document.createElement("div");
    inner.className = "p-5";
    const heading = document.createElement("h3");
    heading.className = "font-display text-2xl tracking-tight";
    heading.textContent = "Upload limit reached";
    const message = document.createElement("p");
    message.className = "text-sm text-ink-muted mt-2";
    const footer = document.createElement("div");
    footer.className = "mt-5 flex justify-end";
    const okButton = document.createElement("button");
    okButton.type = "button";
    okButton.className = "px-4 py-2 text-sm bg-terra text-white rounded-lg hover:bg-terra/90 transition-colors";
    okButton.textContent = "OK";
    okButton.addEventListener("click", () => dialog.close());
    footer.appendChild(okButton);
    inner.append(heading, message, footer);
    dialog.appendChild(inner);
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
    document.body.appendChild(dialog);
    limitDialog = dialog;
    limitDialogMessage = message;
    return { dialog, messageNode: message };
  };
  var showLimitDialog = (message) => {
    const { dialog, messageNode } = ensureDialog();
    messageNode.textContent = message;
    dialog.showModal();
  };
  var readLimitsFromElement = (el) => ({
    maxFilesPerShare: Number(el.dataset.maxFilesPerShare || "0"),
    maxFileSizeBytes: Number(el.dataset.maxFileSizeBytes || "0"),
    maxTotalUploadBytes: Number(el.dataset.maxTotalUploadBytes || "0")
  });

  // scripts/ts/page-drop.ts
  var highlightClasses = ["ring-2", "ring-terra/40"];
  var carriesFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes("Files");
  var isTextField = (target) => target instanceof HTMLElement && (target.isContentEditable || target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement && !["button", "checkbox", "color", "file", "radio", "range", "reset", "submit"].includes(target.type));
  var pad = (value) => String(value).padStart(2, "0");
  var namePastedFile = (file, now = /* @__PURE__ */ new Date()) => {
    if (file.name && !/^image\.[a-z0-9]+$/i.test(file.name)) return file;
    const fromType = (file.type.split("/")[1] ?? "").split("+")[0].replace(/^x-/, "");
    const extension = ((file.name ? file.name.split(".").pop() : "") || fromType || "png").toLowerCase().replace("jpeg", "jpg");
    const stamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    return new File([file], `pasted-${stamp}.${extension}`, { type: file.type, lastModified: file.lastModified });
  };
  var createOverlay = (label) => {
    const overlay = document.createElement("div");
    overlay.setAttribute("aria-hidden", "true");
    overlay.dataset.pageDropOverlay = "";
    overlay.className = "hidden fixed inset-0 z-50 pointer-events-none items-center justify-center bg-cream/80 p-4";
    const frame = document.createElement("div");
    frame.className = "flex h-full w-full items-center justify-center rounded-2xl border-2 border-dashed border-terra bg-terra-wash/60";
    const text = document.createElement("p");
    text.className = "font-display text-3xl text-terra";
    text.textContent = label;
    frame.appendChild(text);
    overlay.appendChild(frame);
    document.body.appendChild(overlay);
    return overlay;
  };
  function enablePageDrop(options) {
    const { dropzone, onFiles, label } = options;
    const isEnabled = options.isEnabled ?? (() => true);
    const overlay = createOverlay(label);
    let depth = 0;
    const show = (visible) => {
      overlay.classList.toggle("hidden", !visible);
      overlay.classList.toggle("flex", visible);
      highlightClasses.forEach((name) => dropzone.classList.toggle(name, visible));
    };
    const reset = () => {
      depth = 0;
      show(false);
    };
    window.addEventListener("dragenter", (event) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      depth += 1;
      show(isEnabled());
    });
    window.addEventListener("dragover", (event) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = isEnabled() ? "copy" : "none";
    });
    window.addEventListener("dragleave", (event) => {
      if (!carriesFiles(event)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) show(false);
    });
    window.addEventListener("drop", (event) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      reset();
      const files = Array.from(event.dataTransfer?.files ?? []);
      if (files.length > 0 && isEnabled()) onFiles(files);
    });
    window.addEventListener("dragend", reset);
    document.addEventListener("paste", (event) => {
      const clipboard = event.clipboardData;
      const files = Array.from(clipboard?.files ?? []);
      if (files.length === 0) return;
      if (isTextField(event.target) && (clipboard?.types ?? []).includes("text/plain")) return;
      event.preventDefault();
      if (isEnabled()) onFiles(files.map((file) => namePastedFile(file)));
    });
  }

  // scripts/ts/clipboard.ts
  async function copyText(value) {
    if (!value) return false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        return true;
      }
    } catch {
    }
    return fallbackCopy(value);
  }
  function fallbackCopy(value) {
    const input = document.createElement("textarea");
    input.value = value;
    input.setAttribute("readonly", "readonly");
    input.style.position = "absolute";
    input.style.left = "-9999px";
    document.body.appendChild(input);
    input.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    document.body.removeChild(input);
    return ok;
  }

  // scripts/ts/dashboard.ts
  (() => {
    const root = document.querySelector("[data-dashboard]");
    if (!root) return;
    const expiredStorageKey = "agora.dashboard.expiredOpen";
    const tabs = Array.from(root.querySelectorAll('[role="tab"][data-tab]'));
    const panels = Array.from(root.querySelectorAll("[data-panel]"));
    const hints = Array.from(root.querySelectorAll("[data-tab-hint]"));
    const newCount = Number(root.getAttribute("data-new-count") ?? "0") || 0;
    let seenSent = false;
    const isTabName = (value) => value === "mine" || value === "received";
    const markReceivedSeen = () => {
      if (seenSent || newCount <= 0) return;
      seenSent = true;
      const csrf = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("agora.csrf.request="))?.slice("agora.csrf.request=".length);
      const headers = csrf ? { "X-CSRF-TOKEN": decodeURIComponent(csrf) } : {};
      const seenUpTo = root.getAttribute("data-seen-up-to");
      if (!seenUpTo) return;
      const query = `?seenUpTo=${encodeURIComponent(seenUpTo)}`;
      void fetch(`/account/received-seen${query}`, { method: "POST", credentials: "same-origin", headers }).then((response) => {
        if (!response.ok) seenSent = false;
      }).catch(() => {
        seenSent = false;
      });
    };
    const selectTab = (name, focus = false) => {
      tabs.forEach((tab) => {
        const on = tab.dataset.tab === name;
        tab.setAttribute("aria-selected", on ? "true" : "false");
        tab.tabIndex = on ? 0 : -1;
        const active = (tab.dataset.activeClass ?? "").split(" ").filter(Boolean);
        const idle = (tab.dataset.idleClass ?? "").split(" ").filter(Boolean);
        tab.classList.remove(...active, ...idle);
        tab.classList.add(...on ? active : idle);
        if (on && focus) tab.focus();
      });
      panels.forEach((panel) => {
        panel.hidden = panel.dataset.panel !== name;
      });
      hints.forEach((hint) => {
        hint.hidden = hint.dataset.tabHint !== name;
      });
      const url = new URL(window.location.href);
      url.searchParams.delete("msg");
      if (name === "received") url.searchParams.set("tab", "received");
      else url.searchParams.delete("tab");
      window.history.replaceState(null, "", url.pathname + url.search + url.hash);
      if (name === "received") markReceivedSeen();
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => {
        if (isTabName(tab.dataset.tab ?? null)) selectTab(tab.dataset.tab);
      });
      tab.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
        event.preventDefault();
        const next = tabs[(index + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
        if (next && isTabName(next.dataset.tab ?? null)) selectTab(next.dataset.tab, true);
      });
    });
    const closeMenu = (menuRoot) => {
      const list = menuRoot.querySelector("[data-menu-list]");
      if (list) list.hidden = true;
      menuRoot.querySelector("[data-menu-button]")?.setAttribute("aria-expanded", "false");
    };
    const closeMenus = (except) => {
      root.querySelectorAll("[data-menu-root]").forEach((menuRoot) => {
        if (menuRoot !== except) closeMenu(menuRoot);
      });
    };
    const placeMenu = (list, button) => {
      const needed = list.offsetHeight + 8;
      const flip = button.getBoundingClientRect().bottom + needed > window.innerHeight && button.getBoundingClientRect().top > needed;
      list.classList.toggle("bottom-full", flip);
      list.classList.toggle("mb-1", flip);
      list.classList.toggle("top-full", !flip);
      list.classList.toggle("mt-1", !flip);
    };
    root.addEventListener("click", (event) => {
      const target = event.target;
      if (target?.closest("[data-menu-list] a, [data-menu-list] button")) closeMenus();
      const button = target?.closest("[data-menu-button]");
      if (!button) return;
      const menuRoot = button.closest("[data-menu-root]");
      const list = menuRoot?.querySelector("[data-menu-list]");
      if (!menuRoot || !list) return;
      closeMenus(menuRoot);
      list.hidden = !list.hidden;
      button.setAttribute("aria-expanded", list.hidden ? "false" : "true");
      if (!list.hidden) placeMenu(list, button);
    });
    document.addEventListener("click", (event) => {
      const target = event.target;
      root.querySelectorAll("[data-menu-root]").forEach((menuRoot) => {
        if (!target || !menuRoot.contains(target)) closeMenu(menuRoot);
      });
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      const open = root.querySelector("[data-menu-list]:not([hidden])");
      if (!open) return;
      const button = open.closest("[data-menu-root]")?.querySelector("[data-menu-button]");
      closeMenus();
      button?.focus();
    });
    const batches = Array.from(root.querySelectorAll("[data-batch-bar]")).map((bar) => ({
      scope: bar.dataset.batchBar ?? "",
      bar,
      clear: bar.querySelector("[data-batch-clear]"),
      count: bar.querySelector("[data-batch-count]"),
      reenable: bar.querySelector("[data-batch-reenable]"),
      del: bar.querySelector("[data-batch-delete]")
    }));
    const selectedFor = (batch) => Array.from(root.querySelectorAll(`input[data-row-select][form="batch-${batch.scope}"]`)).filter((box) => box.checked);
    const updateBatch = (batch) => {
      const selected = selectedFor(batch);
      batch.bar.hidden = selected.length === 0;
      if (selected.length === 0) closeMenus();
      if (batch.count) batch.count.textContent = String(selected.length);
      if (batch.reenable) {
        const ok = selected.some((box) => box.dataset.expired === "true" && box.dataset.direct !== "true");
        batch.reenable.disabled = !ok;
        batch.reenable.title = ok ? "Re-enables the selected expired shares for 24 hours" : "Select an expired share (direct links cannot be re-enabled)";
      }
    };
    const batchOf = (box) => batches.find((batch) => box.getAttribute("form") === `batch-${batch.scope}`);
    root.addEventListener("change", (event) => {
      const target = event.target;
      if (!target?.matches("input[data-row-select]")) return;
      const batch = batchOf(target);
      if (batch) updateBatch(batch);
    });
    let returnFocus = null;
    const rememberTrigger = (from) => {
      returnFocus = from?.closest("[data-menu-root]")?.querySelector("[data-menu-button]") ?? null;
    };
    root.addEventListener(
      "click",
      (event) => {
        const trigger = event.target?.closest("[data-share-delete-trigger]");
        if (trigger) rememberTrigger(trigger);
      },
      true
    );
    document.querySelectorAll("[data-share-delete-dialog], [data-batch-delete-dialog]").forEach((dialog) => {
      dialog.addEventListener("close", () => returnFocus?.focus());
    });
    const batchDialog = document.querySelector("[data-batch-delete-dialog]");
    let pendingBatch = null;
    batches.forEach((batch) => {
      batch.clear?.addEventListener("click", () => {
        root.querySelectorAll(`input[data-row-select][form="batch-${batch.scope}"]`).forEach((box) => {
          box.checked = false;
        });
        updateBatch(batch);
      });
      batch.del?.addEventListener("click", () => {
        rememberTrigger(batch.del);
        closeMenus();
        pendingBatch = batch;
        const summary = batchDialog?.querySelector("[data-batch-delete-summary]");
        if (summary) summary.textContent = `${selectedFor(batch).length} share(s) selected.`;
        batchDialog?.showModal();
      });
      updateBatch(batch);
    });
    batchDialog?.querySelector("[data-batch-delete-cancel]")?.addEventListener("click", () => batchDialog.close());
    batchDialog?.querySelector("[data-batch-delete-confirm]")?.addEventListener("click", () => {
      const batch = pendingBatch;
      batchDialog.close();
      if (!batch) return;
      batch.bar.action = "/shares/delete-batch";
      batch.bar.submit();
    });
    const toggle = root.querySelector("[data-expired-toggle]");
    const expiredList = root.querySelector("[data-expired-list]");
    if (toggle && expiredList) {
      const label = toggle.querySelector("[data-expired-label]");
      const arrow = toggle.querySelector("[data-expired-arrow]");
      const count = toggle.dataset.expiredCount ?? "0";
      const setOpen = (open, persist) => {
        expiredList.hidden = !open;
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
        if (label) label.textContent = `${open ? "Hide" : "Show"} expired (${count})`;
        if (arrow) arrow.style.transform = open ? "rotate(90deg)" : "";
        if (!open) {
          expiredList.querySelectorAll("input[data-row-select]:checked").forEach((box) => {
            box.checked = false;
            const batch = batchOf(box);
            if (batch) updateBatch(batch);
          });
        }
        if (!persist) return;
        try {
          window.localStorage.setItem(expiredStorageKey, open ? "1" : "0");
        } catch {
        }
      };
      let stored = false;
      try {
        stored = window.localStorage.getItem(expiredStorageKey) === "1";
      } catch {
        stored = false;
      }
      setOpen(stored, false);
      toggle.addEventListener("click", () => setOpen(expiredList.hidden, true));
    }
    const copyButton = root.querySelector("[data-copy-upload-link]");
    const linkNode = root.querySelector("[data-upload-link]");
    if (copyButton && linkNode) {
      let timer;
      copyButton.addEventListener("click", async () => {
        const ok = await copyText(linkNode.textContent?.trim() ?? "");
        copyButton.textContent = ok ? "Copied" : "Copy failed";
        window.clearTimeout(timer);
        timer = window.setTimeout(() => {
          copyButton.textContent = "Copy";
        }, 2e3);
      });
    }
    if (tabs.some((tab) => tab.dataset.tab === "received" && tab.getAttribute("aria-selected") === "true")) {
      markReceivedSeen();
    }
  })();

  // scripts/ts/index.ts
  (() => {
    const nodes = document.querySelectorAll("[data-local-datetime]");
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
  (() => {
    const dialog = document.querySelector("[data-share-delete-dialog]");
    if (!dialog) return;
    const nameNode = dialog.querySelector("[data-share-delete-name]");
    const cancelButton = dialog.querySelector("[data-share-delete-cancel]");
    const confirmButton = dialog.querySelector("[data-share-delete-confirm]");
    let pendingForm = null;
    document.querySelectorAll("[data-share-delete-trigger]").forEach((button) => {
      button.addEventListener("click", () => {
        const form = button.closest("[data-share-delete-form]");
        if (!form) return;
        pendingForm = form;
        if (nameNode) {
          nameNode.textContent = form.getAttribute("data-share-name") ?? "";
        }
        dialog.showModal();
      });
    });
    cancelButton?.addEventListener("click", () => dialog.close());
    confirmButton?.addEventListener("click", () => {
      pendingForm?.submit();
      dialog.close();
    });
  })();
  (() => {
    const dialog = document.querySelector("[data-share-details-dialog]");
    if (!dialog) return;
    const nameNode = dialog.querySelector("[data-share-details-name]");
    const senderNameNode = dialog.querySelector("[data-share-details-sender-name]");
    const senderEmailNode = dialog.querySelector("[data-share-details-sender-email]");
    const senderMessageNode = dialog.querySelector("[data-share-details-sender-message]");
    const sentByAgentNode = dialog.querySelector("[data-share-details-sent-by-agent]");
    const listNode = dialog.querySelector("[data-share-details-list]");
    const closeButton = dialog.querySelector("[data-share-details-close]");
    if (!listNode) return;
    const formatBytes = (bytes) => {
      const value = Number(bytes || 0);
      if (!Number.isFinite(value) || value <= 0) return "0 B";
      if (value >= 1024 * 1024 * 1024) return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
      if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
      if (value >= 1024) return `${Math.round(value / 1024)} KB`;
      return `${Math.round(value)} B`;
    };
    const escapeHtml = (value) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
    const getText = (item, key) => {
      const alt = key.charAt(0).toUpperCase() + key.slice(1);
      const value = item[key] ?? item[alt];
      return typeof value === "string" ? value : "";
    };
    const getNumber = (item, key) => {
      const alt = key.charAt(0).toUpperCase() + key.slice(1);
      const value = item[key] ?? item[alt] ?? 0;
      const numeric = Number(value);
      return Number.isFinite(numeric) ? numeric : 0;
    };
    document.querySelectorAll("[data-share-details-trigger]").forEach((button) => {
      button.addEventListener("click", () => {
        const shareName = button.getAttribute("data-share-name") ?? "";
        const senderName = (button.getAttribute("data-share-sender-name") ?? "").trim();
        const senderEmail = (button.getAttribute("data-share-sender-email") ?? "").trim();
        const senderMessageRaw = button.getAttribute("data-share-sender-message") ?? "";
        let senderMessage = "";
        if (senderMessageRaw.length > 0) {
          try {
            const parsed = JSON.parse(senderMessageRaw);
            senderMessage = typeof parsed === "string" ? parsed : "";
          } catch {
            senderMessage = senderMessageRaw;
          }
        }
        const raw = button.getAttribute("data-share-files") ?? "[]";
        let files = [];
        try {
          const parsed = JSON.parse(raw);
          files = Array.isArray(parsed) ? parsed : [];
        } catch {
          files = [];
        }
        files.sort(
          (a, b) => getText(a, "originalFilename").localeCompare(getText(b, "originalFilename"), void 0, {
            sensitivity: "base"
          })
        );
        listNode.innerHTML = "";
        files.forEach((file) => {
          const fileName = getText(file, "originalFilename");
          const fileSize = getNumber(file, "originalSizeBytes");
          const row = document.createElement("tr");
          row.className = "border-b border-border/60 last:border-b-0";
          const nameCell = document.createElement("td");
          nameCell.className = "px-3 py-2 text-sm text-ink-light";
          nameCell.textContent = fileName;
          const sizeCell = document.createElement("td");
          sizeCell.className = "px-3 py-2 text-sm text-ink-muted text-right";
          sizeCell.textContent = formatBytes(fileSize);
          row.append(nameCell, sizeCell);
          listNode.appendChild(row);
        });
        if (files.length === 0) {
          const row = document.createElement("tr");
          row.innerHTML = '<td colspan="2" class="px-3 py-3 text-sm text-ink-muted">No file metadata available.</td>';
          listNode.appendChild(row);
        }
        if (nameNode) {
          nameNode.textContent = shareName;
        }
        if (senderNameNode) {
          senderNameNode.textContent = senderName.length > 0 ? `Sender name: ${senderName}` : "";
        }
        if (senderEmailNode) {
          senderEmailNode.textContent = senderEmail.length > 0 ? `Sender email: ${senderEmail}` : "";
        }
        if (sentByAgentNode) {
          sentByAgentNode.textContent = button.getAttribute("data-share-sent-by-agent") === "true" ? "Sent through the agent interface" : "";
        }
        if (senderMessageNode) {
          if (senderMessage.trim().length > 0) {
            const renderedMessage = escapeHtml(senderMessage).replace(/\r\n|\r|\n/g, "<br />");
            senderMessageNode.innerHTML = `Message:<br />${renderedMessage}`;
          } else {
            senderMessageNode.textContent = "";
          }
        }
        dialog.showModal();
      });
    });
    closeButton?.addEventListener("click", () => dialog.close());
  })();
  (() => {
    const dropzone = document.querySelector("[data-quick-share-dropzone]");
    const fileInput = document.querySelector("[data-quick-share-input]");
    const pickButton = document.querySelector("[data-quick-share-pick]");
    const cancelButton = document.querySelector("[data-quick-share-cancel]");
    const status = document.querySelector("[data-quick-share-status]");
    const uploadList = document.querySelector("[data-quick-share-upload-list]");
    const draftIdInput = document.querySelector("[data-quick-share-draft-id]");
    if (!dropzone || !fileInput || !pickButton || !cancelButton || !status || !uploadList || !draftIdInput?.value) return;
    const limits = readLimitsFromElement(dropzone);
    const draftShareId = draftIdInput.value;
    let activeXhr = null;
    let isUploading = false;
    let cancelRequested = false;
    const setStatus = (text, isError) => {
      status.textContent = text;
      status.classList.remove("text-ink-muted", "text-danger");
      status.classList.add(isError ? "text-danger" : "text-ink-muted");
    };
    const formatBytes = (bytes) => {
      if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
      if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
      return `${bytes} B`;
    };
    const setControls = (uploading) => {
      isUploading = uploading;
      fileInput.disabled = uploading;
      pickButton.disabled = uploading;
      pickButton.title = uploading ? "Upload in progress." : "";
      cancelButton.classList.toggle("hidden", !uploading);
      cancelButton.disabled = !uploading;
      cancelButton.title = uploading ? "Cancel upload and queue immediate cleanup." : "No upload is currently running.";
    };
    const createUploadRow = (file) => {
      const row = document.createElement("li");
      row.className = "rounded-lg border border-border bg-white px-2.5 py-2 min-w-0";
      const name = document.createElement("p");
      name.className = "text-xs text-ink-light truncate";
      name.textContent = file.name;
      const size = document.createElement("p");
      size.className = "text-[11px] text-ink-muted mt-0.5";
      size.textContent = formatBytes(file.size);
      const barWrap = document.createElement("div");
      barWrap.className = "mt-1.5 h-1 bg-cream-dark rounded-full overflow-hidden";
      const bar = document.createElement("div");
      bar.className = "h-full bg-terra transition-all";
      bar.style.width = "0%";
      barWrap.appendChild(bar);
      const state = document.createElement("p");
      state.className = "text-[11px] text-ink-muted mt-1";
      state.textContent = "Pending";
      row.append(name, size, barWrap, state);
      uploadList.appendChild(row);
      return { row, size, barWrap, bar, state };
    };
    const markCanceledCard = (ui) => {
      ui.row.className = "rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0";
      ui.barWrap.style.display = "none";
      ui.state.textContent = "Canceled";
      ui.state.className = "text-[11px] text-ink-muted mt-1";
    };
    const uploadSingleFile = (file, ui) => {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        activeXhr = xhr;
        xhr.open("POST", `/api/uploads/stage?draftShareId=${encodeURIComponent(draftShareId)}`);
        xhr.responseType = "json";
        xhr.upload.addEventListener("progress", (event) => {
          if (!event.lengthComputable) return;
          const percent = Math.min(100, Math.round(event.loaded / event.total * 100));
          ui.bar.style.width = `${percent}%`;
          ui.state.textContent = `Uploading ${formatBytes(event.loaded)} / ${formatBytes(event.total)} (${percent}%)`;
        });
        xhr.addEventListener("load", () => {
          activeXhr = null;
          if (xhr.status >= 200 && xhr.status < 300) {
            const payload2 = xhr.response;
            if (!payload2?.uploadId) {
              reject(new Error("Upload failed."));
              return;
            }
            ui.row.className = "rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-2 min-w-0";
            ui.size.style.display = "none";
            ui.barWrap.style.display = "none";
            ui.state.textContent = formatBytes(file.size);
            ui.state.className = "text-[11px] text-sage mt-1";
            resolve(payload2.uploadId);
            return;
          }
          const payload = xhr.response;
          const message = payload?.error?.trim() || "Upload failed.";
          ui.row.className = "rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0";
          ui.state.textContent = message;
          ui.state.className = "text-[11px] text-danger mt-1";
          reject(new Error(message));
        });
        xhr.addEventListener("abort", () => {
          activeXhr = null;
          reject(new Error("Upload canceled."));
        });
        xhr.addEventListener("error", () => {
          activeXhr = null;
          ui.row.className = "rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0";
          ui.state.textContent = "Upload failed.";
          ui.state.className = "text-[11px] text-danger mt-1";
          reject(new Error("Upload failed."));
        });
        const formData = new FormData();
        formData.append("draftShareId", draftShareId);
        formData.append("file", file, file.name);
        xhr.send(formData);
      });
    };
    const queueCleanupJob = async () => {
      const formData = new FormData();
      formData.append("draftShareId", draftShareId);
      try {
        await fetch("/api/uploads/cancel", { method: "POST", body: formData, credentials: "same-origin" });
        setStatus("Upload canceled. Cleanup queued in background.", false);
      } catch {
        setStatus("Upload canceled. Cleanup request failed; please retry.", true);
      }
    };
    const queueAndUpload = async (files) => {
      if (isUploading) return;
      const selected = Array.from(files ?? []);
      if (selected.length === 0) return;
      const result = validateFileSelection(selected, limits, 0, 0);
      if (!result.ok) {
        showLimitDialog(result.message);
        return;
      }
      uploadList.innerHTML = "";
      cancelRequested = false;
      setControls(true);
      const cards = selected.map((file) => ({ file, ui: createUploadRow(file) }));
      setStatus(`Uploading ${cards.length} file(s)...`, false);
      try {
        for (const card of cards) {
          if (cancelRequested) {
            markCanceledCard(card.ui);
            continue;
          }
          await uploadSingleFile(card.file, card.ui);
        }
        if (cancelRequested) {
          cards.forEach((card) => {
            if (card.ui.state.className.includes("text-danger")) return;
            if (card.ui.state.className.includes("text-sage")) {
              card.ui.state.textContent = "Canceled (cleanup queued)";
              card.ui.state.className = "text-[11px] text-ink-muted mt-1";
              card.ui.row.className = "rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0";
            } else {
              markCanceledCard(card.ui);
            }
          });
          await queueCleanupJob();
          return;
        }
        setStatus("Upload complete. Redirecting to share setup...", false);
        window.location.href = `/shares/new?draftShareId=${encodeURIComponent(draftShareId)}`;
      } catch (error) {
        if (cancelRequested) {
          await queueCleanupJob();
          return;
        }
        setStatus(error instanceof Error ? error.message : "Upload failed.", true);
      } finally {
        setControls(false);
        activeXhr = null;
      }
    };
    cancelButton.addEventListener("click", () => {
      if (!isUploading || cancelRequested) return;
      cancelRequested = true;
      cancelButton.disabled = true;
      cancelButton.title = "Canceling upload...";
      setStatus("Canceling upload...", false);
      activeXhr?.abort();
    });
    pickButton.addEventListener("click", (event) => {
      event.stopPropagation();
      if (isUploading) return;
      fileInput.click();
    });
    dropzone.addEventListener("click", () => {
      if (isUploading) return;
      fileInput.click();
    });
    dropzone.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      if (isUploading) return;
      fileInput.click();
    });
    fileInput.addEventListener("change", () => {
      queueAndUpload(fileInput.files);
      fileInput.value = "";
    });
    enablePageDrop({
      dropzone,
      label: "Drop files to share",
      isEnabled: () => !isUploading,
      onFiles: (files) => void queueAndUpload(files)
    });
    setControls(false);
  })();
})();
//# sourceMappingURL=index.js.map
