(() => {
  "use strict";

  const I18N = window.LANSCAN_I18N;
  const t = (key, vars) => I18N.t(key, vars);

  const state = {
    subnets: [],
    devices: new Map(), // ipv4 -> device object
    rowEls: new Map(), // ipv4 -> <tr> element
    selectedIp: null,
    activeSubnetFilter: "all",
    onlineOnly: false,
    searchQuery: "",
    scanning: false,
    lastScanState: {},
    portScanningIps: new Set(),
    sortCol: 0,
    sortType: "number",
    sortDir: "ascending",
  };

  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

  // DOM refs
  const table = document.getElementById("devices-table");
  const tbody = document.getElementById("devices-tbody");
  const sortStatus = document.getElementById("sort-status");
  const emptyState = document.getElementById("empty-state");
  const btnScan = document.getElementById("btn-scan");
  const btnScanLabel = document.getElementById("btn-scan-label");
  const iconPlay = document.getElementById("icon-play");
  const iconStop = document.getElementById("icon-stop");
  const scanTargetSelect = document.getElementById("scan-target-select");
  const btnEditHostname = document.getElementById("btn-edit-hostname");
  const btnToggleDetails = document.getElementById("btn-toggle-details");
  const detailsPane = document.getElementById("details-pane");
  const scanStatusText = document.getElementById("scan-status-text");
  const progressTrack = document.getElementById("progress-track");
  const progressFill = document.getElementById("progress-fill");
  const searchInput = document.getElementById("search-input");
  const subnetPills = document.getElementById("subnet-pills");
  const filterOnlineOnly = document.getElementById("filter-online-only");
  const filterAutoPorts = document.getElementById("filter-auto-ports");
  const btnScanAllPorts = document.getElementById("btn-scan-all-ports");
  const deviceCounter = document.getElementById("device-counter");

  // Details inspector refs
  const portScanMode = document.getElementById("port-scan-mode");
  const btnPortScan = document.getElementById("btn-port-scan");
  const detPortStatus = document.getElementById("det-port-status");
  const detPortsList = document.getElementById("det-ports-list");
  const detComments = document.getElementById("det-comments");
  const commentsSaved = document.getElementById("comments-saved");

  // Dialog refs
  const configDialog = document.getElementById("config-dialog");
  const editHostnameDialog = document.getElementById("edit-hostname-dialog");
  const editHostnameIp = document.getElementById("edit-hostname-ip");
  const editHostnameInput = document.getElementById("edit-hostname-input");
  const clearDialog = document.getElementById("clear-dialog");
  const customPortsDialog = document.getElementById("custom-ports-dialog");
  const customPortsInput = document.getElementById("custom-ports-input");
  const subnetsConfigList = document.getElementById("subnets-config-list");
  const addSubnetForm = document.getElementById("add-subnet-form");
  const subnetFormError = document.getElementById("subnet-form-error");
  const optAutoQuickPorts = document.getElementById("opt-auto-quick-ports");
  const themeSystemLabel = document.getElementById("theme-system-label");

  // Helpers
  function ipv4ToInt(ip) {
    const parts = String(ip || "").split(".").map(Number);
    if (parts.length !== 4 || parts.some(Number.isNaN)) return 0;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function subnetColor(cidr) {
    const sub = state.subnets.find((s) => s.cidr === cidr);
    return sub ? sub.color : "#64748b";
  }

  function subnetShortLabel(cidr) {
    if (!cidr) return "";
    const sub = state.subnets.find((s) => s.cidr === cidr);
    return sub ? sub.name : cidr;
  }

  function formatRelativeTime(iso) {
    if (!iso) return "—";
    try {
      const dt = new Date(iso);
      return dt.toLocaleString(undefined, {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return iso;
    }
  }

  // Fallback for browsers without closedby="any" (Safari)
  if (!("closedBy" in HTMLDialogElement.prototype)) {
    const outside = (e, dialog) => {
      const r = dialog.getBoundingClientRect();
      return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    };
    for (const dialog of document.querySelectorAll('dialog[closedby="any"]')) {
      let pressedOutside = false;
      dialog.addEventListener("pointerdown", (e) => {
        pressedOutside = outside(e, dialog);
      });
      dialog.addEventListener("pointerup", (e) => {
        if (pressedOutside && outside(e, dialog)) dialog.close();
      });
    }
  }

  // Fallback for browsers without declarative command/commandfor
  if (!("commandForElement" in HTMLButtonElement.prototype)) {
    document.querySelectorAll("button[commandfor][command]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = document.getElementById(btn.getAttribute("commandfor"));
        const cmd = btn.getAttribute("command");
        if (!target) return;
        if (cmd === "show-modal" && typeof target.showModal === "function") target.showModal();
        else if (cmd === "close" && typeof target.close === "function") target.close();
        else if (cmd === "--sort") handleSort(btn);
      });
    });
  }

  // Theme management (follows dark-mode-toggle guidance)
  const colorSchemeMeta = document.querySelector('meta[name="color-scheme"]');
  const osDarkQuery = window.matchMedia("(prefers-color-scheme: dark)");

  function updateThemeControls() {
    let stored = null;
    try {
      stored = localStorage.getItem("color-scheme");
    } catch {}
    const currentMode = stored === "light" || stored === "dark" ? stored : "system";
    if (colorSchemeMeta) {
      colorSchemeMeta.content = currentMode === "system" ? "light dark" : currentMode;
    }
    const osNow = osDarkQuery.matches ? t("theme_mode_dark") : t("theme_mode_light");
    if (themeSystemLabel) {
      themeSystemLabel.textContent = t("theme_system", { mode: osNow });
    }
    document.querySelectorAll('input[name="theme-mode"]').forEach((radio) => {
      radio.checked = radio.value === currentMode;
    });
  }

  document.querySelectorAll('input[name="theme-mode"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      const val = radio.value;
      try {
        if (val === "system") localStorage.removeItem("color-scheme");
        else localStorage.setItem("color-scheme", val);
      } catch {}
      if (colorSchemeMeta) {
        colorSchemeMeta.content = val === "system" ? "light dark" : val;
      }
    });
  });

  window.addEventListener("storage", (e) => {
    if (e.key === "color-scheme") updateThemeControls();
    if (e.key === "lanscan-lang") applyLanguage(e.newValue || "en");
  });
  osDarkQuery.addEventListener("change", updateThemeControls);
  updateThemeControls();

  // Bilingual UI (EN default | ES option)
  function applyLanguage(lang) {
    const active = I18N.setLang(lang);
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll("[data-i18n-html]").forEach((el) => {
      el.innerHTML = t(el.dataset.i18nHtml);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      el.placeholder = t(el.dataset.i18nPlaceholder);
    });
    document.querySelectorAll(".lang-btn[data-set-lang]").forEach((btn) => {
      btn.setAttribute("aria-pressed", String(btn.dataset.setLang === active));
    });
    document.querySelectorAll('input[name="ui-lang"]').forEach((radio) => {
      radio.checked = radio.value === active;
    });

    // Update category <select> options in Edit Device modal
    const typeSelect = document.getElementById("edit-type-input");
    if (typeSelect) {
      [...typeSelect.options].forEach((opt) => {
        opt.textContent = I18N.typeLabel(opt.value);
      });
    }

    // Update responsive stacked table CSS labels
    const lbls = I18N.tableLabels();
    for (let i = 1; i < lbls.length; i++) {
      table.style.setProperty(`--label-${i + 1}`, `"${lbls[i]}"`);
    }

    updateThemeControls();
    renderSubnetsUI();
    updateCountersAndEmpty();
    updateScanStatusUI(state.lastScanState || {});
    renderDetails(state.selectedIp ? state.devices.get(state.selectedIp) : null);
    if (state.activeView === "diagram") renderTopologyDiagram(false);
    if (state.activeView === "audit") renderAuditPanel();
  }

  document.querySelectorAll(".lang-btn[data-set-lang]").forEach((btn) => {
    btn.addEventListener("click", () => applyLanguage(btn.dataset.setLang));
  });
  document.querySelectorAll('input[name="ui-lang"]').forEach((radio) => {
    radio.addEventListener("change", () => applyLanguage(radio.value));
  });

  // Sortable table (follows sortable-table guidance: moves existing <tr> nodes)
  function reorderRows(orderedRows) {
    const move = () => {
      for (const row of orderedRows) {
        if (typeof tbody.moveBefore === "function") tbody.moveBefore(row, null);
        else tbody.appendChild(row);
      }
    };
    move();
  }

  function applySort(announce = false) {
    const rows = [...tbody.rows];
    const factor = state.sortDir === "ascending" ? 1 : -1;
    const idx = state.sortCol;
    const type = state.sortType;

    const getVal = (row) => {
      const cell = row.cells[idx];
      if (!cell) return "";
      return cell.dataset.value ?? cell.textContent.trim();
    };

    rows.sort((a, b) => {
      const va = getVal(a);
      const vb = getVal(b);
      if (type === "number") {
        return factor * (Number(va) - Number(vb));
      }
      return factor * collator.compare(va, vb);
    });

    reorderRows(rows);
    if (announce && sortStatus) {
      const th = table.tHead.rows[0].cells[idx];
      const label = th ? th.textContent.trim() : "column";
      sortStatus.textContent = t("sorted_announce", {
        col: label,
        dir: state.sortDir === "ascending" ? t("ascending") : t("descending"),
        n: rows.length,
      });
    }
  }

  function handleSort(buttonEl) {
    const th = buttonEl.closest("th");
    if (!th) return;
    const dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
    for (const header of table.tHead.rows[0].cells) {
      header.removeAttribute("aria-sort");
    }
    th.setAttribute("aria-sort", dir);
    state.sortCol = th.cellIndex;
    state.sortType = th.dataset.type || "text";
    state.sortDir = dir;
    applySort(true);
  }

  table.addEventListener("command", (event) => {
    if (event.command === "--sort" && event.source) {
      handleSort(event.source);
    }
  });

  // Row creation & in-place update
  function matchesFilters(dev) {
    if (state.activeSubnetFilter !== "all" && dev.subnet_cidr !== state.activeSubnetFilter) {
      return false;
    }
    if (state.onlineOnly && !dev.is_online) {
      return false;
    }
    if (state.searchQuery) {
      const q = state.searchQuery;
      const portsStr = (dev.ports || []).map((p) => `${p.port} ${p.service} ${p.product}`).join(" ");
      const hay = [
        dev.ipv4,
        dev.mac,
        dev.custom_hostname,
        dev.vendor,
        dev.identification,
        dev.dns_name,
        dev.mdns_name,
        dev.smb_name,
        dev.smb_domain,
        dev.subnet_cidr,
        dev.comments,
        portsStr,
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function populateRow(tr, dev) {
    const portsCount = (dev.ports || []).length;
    const pingSortVal = dev.is_online ? (dev.ping_ms != null ? Number(dev.ping_ms) : 0.1) : 999999;
    const pingTitle = dev.is_online
      ? dev.ping_ms != null
        ? `Online (${dev.ping_ms} ms)`
        : "Online"
      : "Offline";
    const subColor = subnetColor(dev.subnet_cidr);
    const subName = subnetShortLabel(dev.subnet_cidr);

    tr.dataset.ip = dev.ipv4;
    tr.classList.toggle("selected", state.selectedIp === dev.ipv4);
    tr.hidden = !matchesFilters(dev);

    const extra = dev.extra || {};
    const cells = tr.children;
    // 0: IPv4 <th scope="row">
    cells[0].dataset.value = String(ipv4ToInt(dev.ipv4));
    cells[0].textContent = dev.ipv4;
    // 1: MAC
    cells[1].textContent = dev.mac || "";
    cells[1].title = dev.mac || "";
    // 2: Hostname (custom or auto-detected from mDNS / SMB / DNS)
    const autoHost = dev.mdns_name || dev.smb_name || dev.dns_name || "";
    if (dev.custom_hostname) {
      cells[2].textContent = dev.custom_hostname;
      cells[2].classList.remove("hostname-placeholder");
      cells[2].title = dev.custom_hostname;
    } else if (autoHost) {
      cells[2].textContent = autoHost;
      cells[2].classList.add("hostname-placeholder");
      cells[2].title = autoHost;
    } else {
      cells[2].textContent = "";
      cells[2].classList.add("hostname-placeholder");
      cells[2].title = "";
    }
    // 3: Ping
    cells[3].dataset.value = String(pingSortVal);
    cells[3].innerHTML = `<span class="ping-dot ${dev.is_online ? "online" : "offline"}" title="${escapeHtml(pingTitle)}" aria-label="${escapeHtml(pingTitle)}"></span>`;
    // 4: Vendor (OUI or protocol-inferred brand)
    const displayVendor = dev.vendor || extra.brand || "";
    cells[4].textContent = displayVendor;
    cells[4].title = displayVendor;
    // 5: Identification (clean protocol/TLS/UPnP/model/category summary)
    const rawIdent = (dev.identification || "").trim();
    const isGarbageIdent =
      /not found|document error|404|403 forbidden|401 unauthorized|access error/i.test(rawIdent) ||
      ["success", "webserver", "index", "login", "error"].includes(rawIdent.toLowerCase());
    const cleanIdent = isGarbageIdent ? "" : rawIdent;
    const specHint = (extra.specs || []).find((s) =>
      /tls|snmp|upnp|modelo|model|pantalla/i.test(s.label || "")
    );
    const displayIdent =
      cleanIdent ||
      (extra.model ? `${extra.brand || ""} ${extra.model}`.trim() : "") ||
      (specHint ? `${extra.brand ? `${extra.brand} · ` : ""}${specHint.value}` : "") ||
      (dev.device_type && dev.device_type !== "unknown" ? I18N.typeLabel(dev.device_type) : "");
    cells[5].textContent = displayIdent;
    cells[5].title = displayIdent;
    // 6: DNS
    cells[6].textContent = dev.dns_name || "";
    cells[6].title = dev.dns_name || "";
    // 7: mDNS
    cells[7].textContent = dev.mdns_name || "";
    cells[7].title = dev.mdns_name || "";
    // 8: SMB Name
    cells[8].textContent = dev.smb_name || "";
    // 9: SMB Domain
    cells[9].textContent = dev.smb_domain || "";
    // 10: Ports
    cells[10].dataset.value = String(portsCount);
    if (state.portScanningIps.has(dev.ipv4)) {
      cells[10].innerHTML = `<span class="port-badge">Escaneando…</span>`;
    } else if (portsCount > 0) {
      const topList = dev.ports.slice(0, 4).map((p) => p.port).join(", ");
      cells[10].innerHTML = `<span class="port-badge" title="Puertos abiertos: ${escapeHtml(dev.ports.map((p) => p.port).join(", "))}">${portsCount} (${escapeHtml(topList)}${portsCount > 4 ? "…" : ""})</span>`;
    } else {
      cells[10].innerHTML = `<span class="muted">—</span>`;
    }
    // 11: Red
    cells[11].dataset.value = dev.subnet_cidr || "";
    if (dev.subnet_cidr) {
      cells[11].innerHTML = `<span class="subnet-tag" title="${escapeHtml(dev.subnet_cidr)}"><span class="pill-dot" style="background:${escapeHtml(subColor)}"></span>${escapeHtml(subName)}</span>`;
    } else {
      cells[11].textContent = "";
    }
  }

  function createRowElement(dev) {
    const tr = document.createElement("tr");
    const th = document.createElement("th");
    th.scope = "row";
    tr.appendChild(th);
    for (let i = 1; i < 12; i++) {
      const td = document.createElement("td");
      if (i === 1) td.className = "mono";
      if (i === 3) td.className = "col-center";
      tr.appendChild(td);
    }
    tr.addEventListener("click", () => selectDevice(dev.ipv4));
    tr.addEventListener("dblclick", () => {
      selectDevice(dev.ipv4);
      openEditHostnameDialog();
    });
    populateRow(tr, dev);
    return tr;
  }

  function upsertDeviceUI(dev, shouldSort = true) {
    state.devices.set(dev.ipv4, dev);
    let tr = state.rowEls.get(dev.ipv4);
    if (!tr) {
      tr = createRowElement(dev);
      state.rowEls.set(dev.ipv4, tr);
      tbody.appendChild(tr);
    } else {
      populateRow(tr, dev);
    }
    if (shouldSort) applySort(false);
    updateCountersAndEmpty();
    if (state.selectedIp === dev.ipv4) renderDetails(dev);
    if (state.activeView === "diagram") scheduleDiagramRender();
    if (state.activeView === "audit") scheduleAuditRender();
  }

  function refreshVisibility() {
    for (const [ip, dev] of state.devices.entries()) {
      const tr = state.rowEls.get(ip);
      if (tr) tr.hidden = !matchesFilters(dev);
    }
    updateCountersAndEmpty();
    if (state.activeView === "diagram") scheduleDiagramRender();
  }

  function updateCountersAndEmpty() {
    let visible = 0;
    let online = 0;
    for (const dev of state.devices.values()) {
      if (matchesFilters(dev)) {
        visible++;
        if (dev.is_online) online++;
      }
    }
    deviceCounter.textContent = t("counter_fmt", { online, visible });
    emptyState.hidden = visible > 0;
    renderSubnetPills();
  }

  function selectDevice(ip) {
    state.selectedIp = ip;
    for (const [rowIp, tr] of state.rowEls.entries()) {
      tr.classList.toggle("selected", rowIp === ip);
    }
    const dev = ip ? state.devices.get(ip) : null;
    btnEditHostname.disabled = !dev;
    renderDetails(dev);
    if (state.activeView === "diagram") highlightDiagramSelection(ip);
  }

  function setDetailField(id, val, isMono = false) {
    const el = document.getElementById(id);
    if (!el) return;
    if (val) {
      el.textContent = val;
      el.classList.remove("muted");
    } else {
      el.textContent = "—";
      el.classList.add("muted");
    }
    el.classList.toggle("mono", isMono && Boolean(val));
  }

  function renderDetails(dev) {
    const profileCard = document.getElementById("det-profile-card");
    const accessCard = document.getElementById("det-access-card");
    const btnEnrichDevice = document.getElementById("btn-enrich-device");
    const btnDetailsEdit = document.getElementById("btn-details-edit");

    if (!dev) {
      if (profileCard) profileCard.hidden = true;
      if (accessCard) accessCard.hidden = true;
      if (btnEnrichDevice) btnEnrichDevice.disabled = true;
      if (btnDetailsEdit) btnDetailsEdit.disabled = true;
      [
        "det-ipv4", "det-ipv6", "det-mac", "det-hostname", "det-location", "det-vendor",
        "det-identification", "det-dns", "det-mdns", "det-smb", "det-smb-domain",
        "det-subnet", "det-ping", "det-lastseen",
      ].forEach((id) => {
        const el = document.getElementById(id);
        if (el) {
          el.textContent = t("no_selection");
          el.classList.add("muted");
        }
      });
      portScanMode.disabled = true;
      btnPortScan.disabled = true;
      detPortStatus.textContent = "";
      detPortsList.innerHTML = `<span class="muted">${escapeHtml(t("no_selection"))}</span>`;
      detComments.value = "";
      detComments.disabled = true;
      return;
    }

    if (btnDetailsEdit) btnDetailsEdit.disabled = false;
    if (btnEnrichDevice) {
      const busy = state.enrichingIps && state.enrichingIps.has(dev.ipv4);
      btnEnrichDevice.disabled = Boolean(busy);
      btnEnrichDevice.textContent = busy ? t("enriching") : t("btn_enrich_device");
    }

    // Render enriched profile card
    const extra = dev.extra || {};
    if (profileCard) {
      profileCard.hidden = false;
      document.getElementById("det-type-icon").innerHTML = deviceIconSvg(dev.device_type || "unknown", 18);
      document.getElementById("det-category").textContent = I18N.typeLabel(dev.device_type || "unknown");
      const brandParts = [extra.brand || dev.vendor, extra.model].filter(Boolean);
      document.getElementById("det-brand-model").textContent = brandParts.join(" · ") || t("no_brand_yet");
      document.getElementById("det-summary").textContent =
        (I18N.getLang() === "es" ? extra.summary : "") ||
        (extra.brand ? `${I18N.typeLabel(dev.device_type || "unknown")} · ${extra.brand}${extra.model ? ` ${extra.model}` : ""}` : t("default_profile_summary"));

      const specsEl = document.getElementById("det-extra-specs");
      const specs = (extra.specs || []).filter((s) => s.label !== "Marca" && s.label !== "Categoría");
      specsEl.hidden = specs.length === 0;
      specsEl.innerHTML = specs
        .map(
          (s) =>
            `<div class="spec-row"><span class="spec-label">${escapeHtml(s.label)}</span><span class="spec-val">${escapeHtml(s.value)}</span></div>`
        )
        .join("");

      const linksEl = document.getElementById("det-quick-links");
      const links = [...(extra.links || [])];
      if (dev.admin_url && !links.some((l) => l.url === dev.admin_url)) {
        links.unshift({ label: "Panel Admin", url: dev.admin_url });
      }
      linksEl.hidden = links.length === 0;
      linksEl.innerHTML = links
        .map(
          (l) =>
            `<a class="quick-link-chip" href="${escapeHtml(l.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(l.label)} ↗</a>`
        )
        .join("");

      const secEl = document.getElementById("det-security-notes");
      const notes = extra.security_notes || [];
      secEl.hidden = notes.length === 0;
      secEl.innerHTML = notes.map((n) => `<div class="sec-note">⚠ ${escapeHtml(n)}</div>`).join("");
    }

    // Render Router / Device Access & Password card
    if (accessCard) {
      const hasSavedCreds = Boolean(dev.admin_user || dev.admin_password || dev.admin_url);
      const isRouter = dev.device_type === "router";
      const defCreds = extra.default_credentials || null;

      if (!hasSavedCreds && !isRouter) {
        accessCard.hidden = true;
      } else {
        accessCard.hidden = false;
        const accessTitle = document.getElementById("det-access-title");
        accessTitle.textContent = isRouter ? t("access_title_router") : t("access_title_saved");
        const bodyEl = document.getElementById("det-access-body");
        const parts = [];

        const adminUrl = dev.admin_url || (isRouter ? `http://${dev.ipv4}` : "");
        if (adminUrl) {
          parts.push(
            `<div class="cred-row"><span class="spec-label">${escapeHtml(t("cred_panel"))}</span><a class="subtle-link mono" href="${escapeHtml(adminUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(adminUrl)} ↗</a></div>`
          );
        }
        if (dev.admin_user) {
          parts.push(
            `<div class="cred-row"><span class="spec-label">${escapeHtml(t("cred_user"))}</span><span class="mono">${escapeHtml(dev.admin_user)}</span></div>`
          );
        }
        if (dev.admin_password) {
          parts.push(`
            <div class="cred-row">
              <span class="spec-label">${escapeHtml(t("cred_pass"))}</span>
              <span class="cred-actions">
                <span id="det-pass-val" class="mono" data-revealed="0">••••••••</span>
                <button type="button" id="btn-det-pass-toggle" class="subtle-action-btn" aria-pressed="false">${escapeHtml(t("btn_show"))}</button>
                <button type="button" id="btn-det-pass-copy" class="subtle-action-btn">${escapeHtml(t("btn_copy"))}</button>
              </span>
            </div>
          `);
        }

        if (isRouter && !dev.admin_password && defCreds) {
          parts.push(`
            <div class="default-creds-box">
              <strong>${escapeHtml(t("factory_ref_title"))}</strong>
              <div><span class="spec-label">${escapeHtml(t("cred_user"))}</span> <span class="mono">${escapeHtml(defCreds.user)}</span></div>
              <div><span class="spec-label">${escapeHtml(t("cred_pass"))}</span> <span class="mono">${escapeHtml(defCreds.password)}</span></div>
              <div class="default-creds-note">${escapeHtml(t("factory_ref_disclaimer"))}</div>
            </div>
          `);
        }

        bodyEl.innerHTML = parts.join("");

        const toggleBtn = document.getElementById("btn-det-pass-toggle");
        const copyBtn = document.getElementById("btn-det-pass-copy");
        const passValEl = document.getElementById("det-pass-val");
        if (toggleBtn && passValEl) {
          toggleBtn.addEventListener("click", () => {
            const revealed = passValEl.dataset.revealed === "1";
            passValEl.dataset.revealed = revealed ? "0" : "1";
            passValEl.textContent = revealed ? "••••••••" : dev.admin_password;
            toggleBtn.textContent = revealed ? t("btn_show") : t("btn_hide");
            toggleBtn.setAttribute("aria-pressed", String(!revealed));
          });
        }
        if (copyBtn) {
          copyBtn.addEventListener("click", async () => {
            try {
              await navigator.clipboard.writeText(dev.admin_password);
              copyBtn.textContent = t("btn_copied");
              setTimeout(() => {
                copyBtn.textContent = t("btn_copy");
              }, 1400);
            } catch {}
          });
        }
      }
    }

    setDetailField("det-ipv4", dev.ipv4, true);
    setDetailField("det-ipv6", dev.ipv6, true);
    setDetailField("det-mac", dev.mac, true);
    setDetailField("det-hostname", dev.custom_hostname);
    setDetailField("det-location", dev.location);
    setDetailField("det-vendor", dev.vendor);
    setDetailField("det-identification", dev.identification);
    setDetailField("det-dns", dev.dns_name);
    setDetailField("det-mdns", dev.mdns_name);
    setDetailField("det-smb", dev.smb_name);
    setDetailField("det-smb-domain", dev.smb_domain);
    setDetailField("det-subnet", dev.subnet_cidr ? `${subnetShortLabel(dev.subnet_cidr)} (${dev.subnet_cidr})` : "");
    setDetailField(
      "det-ping",
      dev.is_online
        ? `Online${dev.ping_ms != null ? ` (${dev.ping_ms} ms)` : ""}`
        : "Offline"
    );
    setDetailField("det-lastseen", formatRelativeTime(dev.last_seen));

    const isPortScanning = state.portScanningIps.has(dev.ipv4);
    portScanMode.disabled = isPortScanning;
    btnPortScan.disabled = isPortScanning;
    btnPortScan.textContent = isPortScanning ? t("scanning_short") : t("btn_scan_ports");
    detPortStatus.textContent = isPortScanning
      ? t("running_nmap")
      : dev.last_port_scan
      ? t("updated_at", { t: formatRelativeTime(dev.last_port_scan) })
      : "";

    const ports = dev.ports || [];
    if (ports.length === 0) {
      detPortsList.innerHTML = `<span class="muted">${escapeHtml(dev.last_port_scan ? t("no_open_ports") : t("not_scanned_ports"))}</span>`;
    } else {
      detPortsList.innerHTML = ports
        .map((p) => {
          const ver = [p.product, p.version, p.extrainfo].filter(Boolean).join(" ");
          const link = p.web_url
            ? `<a class="port-open-link" href="${escapeHtml(p.web_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(t("open_link"))}</a>`
            : "";
          return `
            <div class="port-item">
              <div class="port-item-main">
                <span class="port-num">${p.port}/${escapeHtml(p.protocol)}</span>
                <span class="port-svc">${escapeHtml(p.service || t("unknown_service"))}</span>
                ${ver ? `<span class="port-ver" title="${escapeHtml(ver)}">${escapeHtml(ver)}</span>` : ""}
              </div>
              ${link}
            </div>`;
        })
        .join("");
    }

    if (document.activeElement !== detComments) {
      detComments.value = dev.comments || "";
    }
    detComments.disabled = false;
  }

  // Subnets rendering (dropdown, filter pills, and config dialog)
  function renderSubnetsUI() {
    const prevVal = scanTargetSelect.value || "all";
    scanTargetSelect.innerHTML =
      `<option value="all">${escapeHtml(t("all_networks_opt", { n: state.subnets.filter((s) => s.enabled).length }))}</option>` +
      state.subnets
        .map(
          (s) =>
            `<option value="${s.id}">${escapeHtml(s.name)} (${escapeHtml(s.cidr)})</option>`
        )
        .join("");
    if ([...scanTargetSelect.options].some((o) => o.value === prevVal)) {
      scanTargetSelect.value = prevVal;
    }

    renderSubnetPills();
    renderSubnetsConfigList();
  }

  function renderSubnetPills() {
    const counts = new Map();
    for (const dev of state.devices.values()) {
      counts.set(dev.subnet_cidr, (counts.get(dev.subnet_cidr) || 0) + 1);
    }

    const pills = [
      `<button type="button" class="pill-btn" data-cidr="all" aria-pressed="${state.activeSubnetFilter === "all"}">${escapeHtml(t("all_networks_pill", { n: state.devices.size }))}</button>`,
      ...state.subnets.map((s) => {
        const cnt = counts.get(s.cidr) || 0;
        const pressed = state.activeSubnetFilter === s.cidr;
        return `<button type="button" class="pill-btn" data-cidr="${escapeHtml(s.cidr)}" aria-pressed="${pressed}">
          <span class="pill-dot" style="background:${escapeHtml(s.color)}"></span>
          ${escapeHtml(s.name)} <span class="mono">${escapeHtml(s.cidr)}</span> (${cnt})
        </button>`;
      }),
    ];
    subnetPills.innerHTML = pills.join("");
    subnetPills.querySelectorAll(".pill-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.activeSubnetFilter = btn.dataset.cidr;
        refreshVisibility();
      });
    });
  }

  function renderSubnetsConfigList() {
    if (state.subnets.length === 0) {
      subnetsConfigList.innerHTML = `<p class="muted">${escapeHtml(t("cfg_no_subnets"))}</p>`;
      return;
    }
    subnetsConfigList.innerHTML = state.subnets
      .map(
        (s) => `
        <div class="subnet-row">
          <div class="subnet-row-left">
            <input type="checkbox" data-toggle-subnet="${s.id}" ${s.enabled ? "checked" : ""} aria-label="${escapeHtml(s.name)}">
            <span class="pill-dot" style="background:${escapeHtml(s.color)}"></span>
            <div>
              <strong>${escapeHtml(s.name)}</strong>
              <div class="subnet-cidr-code">${escapeHtml(s.cidr)} (${escapeHtml(s.start_ip)} – ${escapeHtml(s.end_ip)})</div>
            </div>
          </div>
          <button type="button" class="secondary-btn" data-delete-subnet="${s.id}">${escapeHtml(t("btn_delete"))}</button>
        </div>`
      )
      .join("");

    subnetsConfigList.querySelectorAll("[data-toggle-subnet]").forEach((cb) => {
      cb.addEventListener("change", async () => {
        const id = Number(cb.dataset.toggleSubnet);
        const sub = state.subnets.find((x) => x.id === id);
        if (!sub) return;
        await fetch(`/api/subnets/${id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: sub.name,
            cidr: sub.cidr,
            enabled: cb.checked,
            color: sub.color,
          }),
        });
        await reloadSubnets();
      });
    });

    subnetsConfigList.querySelectorAll("[data-delete-subnet]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.deleteSubnet);
        await fetch(`/api/subnets/${id}`, { method: "DELETE" });
        await reloadSubnets();
      });
    });
  }

  async function reloadSubnets() {
    const res = await fetch("/api/subnets");
    state.subnets = await res.json();
    renderSubnetsUI();
  }

  // Scan controls
  function updateScanStatusUI(st) {
    state.lastScanState = st || {};
    state.scanning = Boolean(st.running);
    btnScan.classList.toggle("scanning", state.scanning);
    iconPlay.hidden = state.scanning;
    iconStop.hidden = !state.scanning;
    btnScanLabel.textContent = state.scanning ? t("stop_scan") : t("start_scan");
    scanTargetSelect.disabled = state.scanning;

    if (st.running && st.phase === "ports") {
      scanStatusText.textContent = t("status_port_phase", {
        done: st.port_done || 0,
        total: st.port_total || 0,
      });
    } else if (st.running && st.current_range) {
      scanStatusText.textContent = t("status_scanning_range", {
        range: st.current_range.replace(" a ", " – "),
        count: st.found_count || 0,
      });
    } else if (st.completed_subnets > 0) {
      scanStatusText.textContent = t("status_scan_done", {
        count: st.found_count || 0,
        subnets: st.total_subnets || st.completed_subnets,
      });
    } else {
      scanStatusText.textContent = t("status_ready");
    }

    if (btnScanAllPorts) btnScanAllPorts.disabled = state.scanning;
    progressTrack.classList.toggle("visible", state.scanning);
    progressFill.style.width = `${st.progress || 0}%`;
  }

  btnScan.addEventListener("click", async () => {
    if (state.scanning) {
      await fetch("/api/scan/stop", { method: "POST" });
      return;
    }
    const sel = scanTargetSelect.value;
    const body = sel === "all" ? {} : { subnet_ids: [Number(sel)] };
    const res = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      scanStatusText.textContent = err.detail || "No se pudo iniciar el escaneo";
    }
  });

  // Edit Device full details dialog
  const editTypeInput = document.getElementById("edit-type-input");
  const editVendorInput = document.getElementById("edit-vendor-input");
  const editIdentInput = document.getElementById("edit-ident-input");
  const editLocationInput = document.getElementById("edit-location-input");
  const editAdminUrlInput = document.getElementById("edit-admin-url-input");
  const editAdminUserInput = document.getElementById("edit-admin-user-input");
  const editAdminPassInput = document.getElementById("edit-admin-pass-input");
  const editCommentsInput = document.getElementById("edit-comments-input");
  const btnToggleEditPass = document.getElementById("btn-toggle-edit-pass");
  const btnDetailsEdit = document.getElementById("btn-details-edit");
  const btnEditCreds = document.getElementById("btn-edit-creds");

  if (btnToggleEditPass && editAdminPassInput) {
    btnToggleEditPass.addEventListener("click", () => {
      const showing = editAdminPassInput.type === "text";
      editAdminPassInput.type = showing ? "password" : "text";
      btnToggleEditPass.textContent = showing ? t("btn_show") : t("btn_hide");
      btnToggleEditPass.setAttribute("aria-pressed", String(!showing));
      btnToggleEditPass.setAttribute("aria-label", showing ? t("btn_show") : t("btn_hide"));
    });
  }

  function openEditHostnameDialog() {
    if (!state.selectedIp) return;
    const dev = state.devices.get(state.selectedIp);
    if (!dev) return;
    editHostnameIp.textContent = `${dev.ipv4}${dev.vendor ? ` (${dev.vendor})` : ""}`;
    editHostnameInput.value = dev.custom_hostname || "";
    if (editTypeInput) editTypeInput.value = dev.device_type || "unknown";
    if (editVendorInput) editVendorInput.value = dev.vendor || "";
    if (editIdentInput) editIdentInput.value = dev.identification || "";
    if (editLocationInput) editLocationInput.value = dev.location || "";
    if (editAdminUrlInput) editAdminUrlInput.value = dev.admin_url || (dev.device_type === "router" ? `http://${dev.ipv4}` : "");
    if (editAdminUserInput) editAdminUserInput.value = dev.admin_user || "";
    if (editAdminPassInput) {
      editAdminPassInput.value = dev.admin_password || "";
      editAdminPassInput.type = "password";
    }
    if (btnToggleEditPass) {
      btnToggleEditPass.textContent = t("btn_show");
      btnToggleEditPass.setAttribute("aria-pressed", "false");
    }
    if (editCommentsInput) editCommentsInput.value = dev.comments || "";
    editHostnameDialog.showModal();
    editHostnameInput.focus();
  }

  btnEditHostname.addEventListener("click", openEditHostnameDialog);
  if (btnDetailsEdit) btnDetailsEdit.addEventListener("click", openEditHostnameDialog);
  if (btnEditCreds) btnEditCreds.addEventListener("click", openEditHostnameDialog);

  editHostnameDialog.addEventListener("close", async () => {
    const action = editHostnameDialog.returnValue;
    editHostnameDialog.returnValue = "";
    if (action === "save" && state.selectedIp) {
      const payload = {
        custom_hostname: editHostnameInput.value,
        device_type: editTypeInput ? editTypeInput.value : undefined,
        vendor: editVendorInput ? editVendorInput.value : undefined,
        identification: editIdentInput ? editIdentInput.value : undefined,
        location: editLocationInput ? editLocationInput.value : undefined,
        admin_url: editAdminUrlInput ? editAdminUrlInput.value : undefined,
        admin_user: editAdminUserInput ? editAdminUserInput.value : undefined,
        admin_password: editAdminPassInput ? editAdminPassInput.value : undefined,
        comments: editCommentsInput ? editCommentsInput.value : undefined,
      };
      const res = await fetch(`/api/devices/${encodeURIComponent(state.selectedIp)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) upsertDeviceUI(await res.json());
    }
  });

  // Clear Results confirmation dialog
  clearDialog.addEventListener("close", async () => {
    const action = clearDialog.returnValue;
    clearDialog.returnValue = "";
    if (action === "confirm") {
      const q =
        state.activeSubnetFilter !== "all"
          ? `?subnet_cidr=${encodeURIComponent(state.activeSubnetFilter)}`
          : "";
      await fetch(`/api/devices${q}`, { method: "DELETE" });
      await loadBootstrap();
    }
  });

  // Add Subnet form
  addSubnetForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    subnetFormError.textContent = "";
    const name = document.getElementById("new-subnet-name").value.trim();
    const cidr = document.getElementById("new-subnet-cidr").value.trim();
    const color = document.getElementById("new-subnet-color").value;
    const res = await fetch("/api/subnets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, cidr, color, enabled: true }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      subnetFormError.textContent = err.detail || "CIDR inválido (ej. 192.168.1.0/24)";
      return;
    }
    addSubnetForm.reset();
    await reloadSubnets();
  });

  // Settings option (synced between Config dialog and main Filter Bar)
  async function setAutoQuickPorts(enabled) {
    optAutoQuickPorts.checked = enabled;
    if (filterAutoPorts) filterAutoPorts.checked = enabled;
    await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auto_quick_ports: enabled }),
    });
  }

  optAutoQuickPorts.addEventListener("change", () => setAutoQuickPorts(optAutoQuickPorts.checked));
  if (filterAutoPorts) {
    filterAutoPorts.addEventListener("change", () => setAutoQuickPorts(filterAutoPorts.checked));
  }
  if (btnScanAllPorts) {
    btnScanAllPorts.addEventListener("click", async () => {
      const res = await fetch("/api/port-scan-all", { method: "POST" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        scanStatusText.textContent = err.detail || "Unable to start port scan";
      }
    });
  }

  // Port scan actions
  async function triggerPortScan(ip, mode, customPorts = "") {
    state.portScanningIps.add(ip);
    const dev = state.devices.get(ip);
    if (dev) upsertDeviceUI(dev, false);
    try {
      const res = await fetch(`/api/devices/${encodeURIComponent(ip)}/port-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, custom_ports: customPorts }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.device) upsertDeviceUI(data.device, false);
      } else {
        const err = await res.json().catch(() => ({}));
        detPortStatus.textContent = err.detail || "Error al escanear puertos";
      }
    } finally {
      state.portScanningIps.delete(ip);
      const cur = state.devices.get(ip);
      if (cur) upsertDeviceUI(cur, false);
    }
  }

  btnPortScan.addEventListener("click", () => {
    if (!state.selectedIp) return;
    const mode = portScanMode.value;
    if (mode === "custom") {
      customPortsDialog.showModal();
      return;
    }
    triggerPortScan(state.selectedIp, mode);
  });

  customPortsDialog.addEventListener("close", () => {
    const action = customPortsDialog.returnValue;
    customPortsDialog.returnValue = "";
    if (action === "scan" && state.selectedIp) {
      triggerPortScan(state.selectedIp, "custom", customPortsInput.value);
    }
  });

  // Auto-save comments on debounce / blur
  let commentTimer = null;
  async function saveComments() {
    if (!state.selectedIp) return;
    const ip = state.selectedIp;
    const res = await fetch(`/api/devices/${encodeURIComponent(ip)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ comments: detComments.value }),
    });
    if (res.ok) {
      const dev = await res.json();
      state.devices.set(ip, dev);
      commentsSaved.textContent = t("comments_saved");
      setTimeout(() => {
        if (commentsSaved.textContent === t("comments_saved")) commentsSaved.textContent = "";
      }, 1500);
    }
  }

  detComments.addEventListener("input", () => {
    clearTimeout(commentTimer);
    commentTimer = setTimeout(saveComments, 650);
  });
  detComments.addEventListener("blur", saveComments);

  // Filters & inspector toggle
  searchInput.addEventListener("input", () => {
    state.searchQuery = searchInput.value.trim().toLowerCase();
    refreshVisibility();
  });

  filterOnlineOnly.addEventListener("change", () => {
    state.onlineOnly = filterOnlineOnly.checked;
    refreshVisibility();
  });

  btnToggleDetails.addEventListener("click", () => {
    const collapsed = detailsPane.classList.toggle("collapsed");
    btnToggleDetails.classList.toggle("active", !collapsed);
    btnToggleDetails.setAttribute("aria-pressed", String(!collapsed));
  });

  // Live SSE updates
  function connectEvents() {
    const es = new EventSource("/api/events");
    es.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === "status") {
          updateScanStatusUI(msg.data);
        } else if (msg.type === "device") {
          upsertDeviceUI(msg.data);
        } else if (msg.type === "scan_complete") {
          updateScanStatusUI(msg.data);
          loadBootstrap();
        } else if (msg.type === "cleared") {
          loadBootstrap();
        }
      } catch {}
    };
    es.onerror = () => {
      es.close();
      setTimeout(connectEvents, 3000);
    };
  }

  async function loadBootstrap() {
    const res = await fetch("/api/bootstrap");
    const data = await res.json();
    state.subnets = data.subnets || [];
    const autoPortsOn = data.settings?.auto_quick_ports === "true";
    optAutoQuickPorts.checked = autoPortsOn;
    if (filterAutoPorts) filterAutoPorts.checked = autoPortsOn;

    // Rebuild table rows cleanly on full bootstrap
    const incomingIps = new Set((data.devices || []).map((d) => d.ipv4));
    for (const [ip, tr] of state.rowEls.entries()) {
      if (!incomingIps.has(ip)) {
        tr.remove();
        state.rowEls.delete(ip);
        state.devices.delete(ip);
      }
    }
    for (const dev of data.devices || []) {
      upsertDeviceUI(dev, false);
    }
    applySort(false);
    renderSubnetsUI();
    updateScanStatusUI(data.scan_state || {});
    updateCountersAndEmpty();

    if (state.selectedIp && state.devices.has(state.selectedIp)) {
      renderDetails(state.devices.get(state.selectedIp));
    } else if (state.selectedIp) {
      selectDevice(null);
    }
    if (state.activeView === "diagram") scheduleDiagramRender();
    if (state.activeView === "audit") scheduleAuditRender();
  }

  // =========================================================================
  // Detailed Multi-Tone Illustrated Device Drawings (48x48 SVG artwork)
  // =========================================================================
  const DEVICE_DRAWINGS = {
    internet: `
      <circle cx="24" cy="24" r="17" fill="#0ea5e9" fill-opacity="0.16" stroke="#0284c7" stroke-width="2"/>
      <ellipse cx="24" cy="24" rx="8.5" ry="17" fill="none" stroke="#0284c7" stroke-width="1.6"/>
      <path d="M8 18h32M8 30h32" stroke="#0284c7" stroke-width="1.5"/>
      <circle cx="24" cy="18" r="2.2" fill="#38bdf8"/>
      <circle cx="17" cy="30" r="2.2" fill="#22c55e"/>
      <circle cx="31" cy="24" r="2.2" fill="#6366f1"/>
    `,
    router: `
      <path d="M13 24L10 9M35 24L38 9" stroke="#64748b" stroke-width="2.4" stroke-linecap="round"/>
      <circle cx="10" cy="8.5" r="2" fill="#3b82f6"/>
      <circle cx="38" cy="8.5" r="2" fill="#3b82f6"/>
      <path d="M17.5 14.5a9 9 0 0 1 13 0M20.5 18a5 5 0 0 1 7 0" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round"/>
      <rect x="6" y="24" width="36" height="14" rx="4" fill="#334155" stroke="#1e293b" stroke-width="1.5"/>
      <rect x="8" y="26" width="32" height="3.5" rx="1.5" fill="#475569"/>
      <circle cx="13" cy="33" r="2" fill="#22c55e"/>
      <circle cx="19" cy="33" r="2" fill="#22c55e"/>
      <circle cx="25" cy="33" r="2" fill="#38bdf8"/>
      <rect x="31" y="31.5" width="7" height="3" rx="1" fill="#94a3b8"/>
    `,
    nas: `
      <rect x="8" y="6" width="32" height="36" rx="4" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
      <rect x="11" y="10" width="5.5" height="24" rx="1.2" fill="#334155" stroke="#64748b" stroke-width="0.9"/>
      <rect x="18" y="10" width="5.5" height="24" rx="1.2" fill="#334155" stroke="#64748b" stroke-width="0.9"/>
      <rect x="25" y="10" width="5.5" height="24" rx="1.2" fill="#334155" stroke="#64748b" stroke-width="0.9"/>
      <rect x="32" y="10" width="5.5" height="24" rx="1.2" fill="#334155" stroke="#64748b" stroke-width="0.9"/>
      <circle cx="13.7" cy="13.5" r="1.2" fill="#22c55e"/>
      <circle cx="20.7" cy="13.5" r="1.2" fill="#22c55e"/>
      <circle cx="27.7" cy="13.5" r="1.2" fill="#22c55e"/>
      <circle cx="34.7" cy="13.5" r="1.2" fill="#38bdf8"/>
      <rect x="12" y="36.8" width="10" height="2.4" rx="1.2" fill="#0ea5e9"/>
      <circle cx="35" cy="38" r="1.6" fill="#22c55e"/>
    `,
    tv: `
      <rect x="5" y="8" width="38" height="25" rx="3" fill="#0f172a" stroke="#475569" stroke-width="1.8"/>
      <rect x="7.5" y="10.5" width="33" height="20" rx="1.5" fill="#1d4ed8"/>
      <polygon points="7.5,10.5 27,10.5 16,30.5 7.5,30.5" fill="#38bdf8" fill-opacity="0.32"/>
      <polygon points="27,10.5 40.5,10.5 40.5,30.5 16,30.5" fill="#7c3aed" fill-opacity="0.3"/>
      <rect x="21" y="33" width="6" height="4.5" fill="#64748b"/>
      <rect x="14" y="37.5" width="20" height="2.6" rx="1.3" fill="#475569"/>
      <circle cx="38" cy="31.5" r="1" fill="#22c55e"/>
    `,
    camera: `
      <path d="M10 38v-8h6" fill="none" stroke="#64748b" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
      <rect x="11" y="14" width="24" height="16" rx="4" fill="#f8fafc" stroke="#475569" stroke-width="1.8"/>
      <path d="M35 17l7-3.5v17L35 27z" fill="#cbd5e1" stroke="#475569" stroke-width="1.5" stroke-linejoin="round"/>
      <circle cx="22" cy="22" r="5.5" fill="#0f172a" stroke="#334155" stroke-width="1.5"/>
      <circle cx="22" cy="22" r="2.6" fill="#0ea5e9"/>
      <circle cx="20.5" cy="20.5" r="1" fill="#ffffff"/>
      <circle cx="30.5" cy="17.5" r="1.5" fill="#ef4444"/>
    `,
    printer: `
      <rect x="13" y="6" width="22" height="12" rx="1.5" fill="#f8fafc" stroke="#64748b" stroke-width="1.5"/>
      <path d="M17 10h14M17 13.5h10" stroke="#94a3b8" stroke-width="1.4" stroke-linecap="round"/>
      <rect x="6" y="16" width="36" height="16" rx="3.5" fill="#475569" stroke="#334155" stroke-width="1.5"/>
      <circle cx="36" cy="21" r="1.8" fill="#38bdf8"/>
      <circle cx="31" cy="21" r="1.4" fill="#22c55e"/>
      <rect x="12" y="27" width="24" height="13" rx="1.5" fill="#ffffff" stroke="#64748b" stroke-width="1.5"/>
      <path d="M16 31.5h16M16 35.5h11" stroke="#94a3b8" stroke-width="1.5" stroke-linecap="round"/>
    `,
    computer: `
      <rect x="8" y="9" width="32" height="22" rx="2.5" fill="#0f172a" stroke="#64748b" stroke-width="1.8"/>
      <rect x="10.5" y="11.5" width="27" height="17" rx="1" fill="#2563eb"/>
      <polygon points="10.5,11.5 28,11.5 19,28.5 10.5,28.5" fill="#60a5fa" fill-opacity="0.38"/>
      <path d="M4 32.5h40l-2.5 5a2 2 0 0 1-1.8 1H8.3a2 2 0 0 1-1.8-1L4 32.5z" fill="#cbd5e1" stroke="#64748b" stroke-width="1.4"/>
      <rect x="20" y="34" width="8" height="1.8" rx="0.9" fill="#64748b"/>
    `,
    mobile: `
      <rect x="14" y="5" width="20" height="38" rx="4.5" fill="#1e293b" stroke="#64748b" stroke-width="1.8"/>
      <rect x="16.5" y="8.5" width="15" height="30" rx="2" fill="#0ea5e9"/>
      <polygon points="16.5,8.5 31.5,8.5 31.5,24 16.5,32" fill="#6366f1" fill-opacity="0.45"/>
      <rect x="21" y="9.8" width="6" height="1.6" rx="0.8" fill="#0f172a"/>
      <rect x="20.5" y="35.8" width="7" height="1.5" rx="0.75" fill="#ffffff" fill-opacity="0.8"/>
    `,
    iot: `
      <path d="M15 11a13 13 0 0 1 18 0M18.5 14.5a8 8 0 0 1 11 0" fill="none" stroke="#38bdf8" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="24" cy="25" r="9.5" fill="#fbbf24" fill-opacity="0.28" stroke="#f59e0b" stroke-width="2"/>
      <circle cx="24" cy="25" r="5" fill="#f59e0b"/>
      <rect x="20" y="34.5" width="8" height="5" rx="1.5" fill="#64748b"/>
      <path d="M21 41h6" stroke="#475569" stroke-width="2" stroke-linecap="round"/>
    `,
    media_player: `
      <rect x="6" y="13" width="36" height="22" rx="5" fill="#1e293b" stroke="#475569" stroke-width="1.8"/>
      <circle cx="24" cy="24" r="7.5" fill="#ef4444"/>
      <polygon points="22,20.5 28.5,24 22,27.5" fill="#ffffff"/>
      <circle cx="11.5" cy="18.5" r="1.4" fill="#22c55e"/>
    `,
    console: `
      <rect x="5" y="13" width="10" height="22" rx="4" fill="#3b82f6" stroke="#1d4ed8" stroke-width="1.4"/>
      <rect x="33" y="13" width="10" height="22" rx="4" fill="#ef4444" stroke="#b91c1c" stroke-width="1.4"/>
      <rect x="15" y="13" width="18" height="22" fill="#1e293b" stroke="#475569" stroke-width="1.4"/>
      <rect x="17.5" y="16" width="13" height="16" rx="1" fill="#38bdf8" fill-opacity="0.3"/>
      <circle cx="10" cy="20" r="2" fill="#0f172a"/>
      <circle cx="38" cy="27" r="2" fill="#0f172a"/>
      <circle cx="38" cy="19" r="1.2" fill="#ffffff"/>
      <circle cx="10" cy="27" r="1.2" fill="#ffffff"/>
    `,
    unknown: `
      <rect x="9" y="9" width="30" height="30" rx="6" fill="#475569" fill-opacity="0.18" stroke="#64748b" stroke-width="1.8"/>
      <rect x="15" y="15" width="18" height="18" rx="3" fill="#334155"/>
      <circle cx="24" cy="24" r="3.5" fill="#38bdf8"/>
      <circle cx="19" cy="19" r="1.2" fill="#22c55e"/>
    `,
  };

  // =========================================================================
  // Device Category Vector Icons (inline small SVG paths for Details card)
  // =========================================================================
  const ICON_PATHS = {
    internet: `<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a13 13 0 0 1 0 18M12 3a13 13 0 0 0 0 18" fill="none" stroke="currentColor" stroke-width="1.5"/>`,
    router: `<rect x="3" y="13" width="18" height="6" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="7" cy="16" r="1" fill="currentColor"/><circle cx="11" cy="16" r="1" fill="currentColor"/><path d="M7 13V8m10 5V8M5 6a4 4 0 0 1 4 0m6 0a4 4 0 0 1 4 0" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>`,
    nas: `<rect x="4" y="3" width="16" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><line x1="8" y1="7" x2="8" y2="17" stroke="currentColor" stroke-width="1.6"/><line x1="12" y1="7" x2="12" y2="17" stroke="currentColor" stroke-width="1.6"/><line x1="16" y1="7" x2="16" y2="17" stroke="currentColor" stroke-width="1.6"/>`,
    tv: `<rect x="2.5" y="4" width="19" height="13" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M8 20h8M12 17v3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>`,
    camera: `<path d="M3 8.5a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7z" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M16 10l5-2.5v9L16 14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>`,
    printer: `<path d="M7 8V3h10v5M5 17H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-1" fill="none" stroke="currentColor" stroke-width="1.8"/><rect x="7" y="14" width="10" height="7" rx="1" fill="none" stroke="currentColor" stroke-width="1.8"/>`,
    computer: `<rect x="3" y="4" width="18" height="12" rx="1.8" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M1.5 19h21" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>`,
    mobile: `<rect x="7" y="2.5" width="10" height="19" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="18.2" r="0.9" fill="currentColor"/>`,
    iot: `<rect x="7" y="7" width="10" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M9 3v4m6-4v4M9 17v4m6-4v4M3 9h4m-4 6h4m10-6h4m-4 6h4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>`,
    media_player: `<rect x="3" y="6" width="18" height="12" rx="2.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M10 9.5l5 2.5-5 2.5v-5z" fill="currentColor"/>`,
    console: `<path d="M6 9h12a4 4 0 0 1 3.8 5.2l-.7 2.2A2 2 0 0 1 17.5 17L15 15H9l-2.5 2a2 2 0 0 1-3.6-.6l-.7-2.2A4 4 0 0 1 6 9z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M7.5 12h3M9 10.5v3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="15.5" cy="11.5" r="0.9" fill="currentColor"/><circle cx="17.2" cy="13.2" r="0.9" fill="currentColor"/>`,
    unknown: `<rect x="4" y="4" width="16" height="16" rx="3" fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>`,
  };

  function deviceIconSvg(type, size = 18) {
    const inner = DEVICE_DRAWINGS[type] || DEVICE_DRAWINGS.unknown;
    return `<svg viewBox="0 0 48 48" width="${size + 8}" height="${size + 8}" aria-hidden="true">${inner}</svg>`;
  }

  // =========================================================================
  // Tabs: Tabla | Diagrama de Red | Auditoría y Mejoras (modern-web-guidance tabs)
  // =========================================================================
  state.activeView = "table";
  state.enrichingIps = new Set();
  state.auditCategory = "all";
  state.lastAudit = null;

  const tabTable = document.getElementById("tab-table");
  const tabDiagram = document.getElementById("tab-diagram");
  const tabAudit = document.getElementById("tab-audit");
  const panelTable = document.getElementById("panel-table");
  const panelDiagram = document.getElementById("panel-diagram");
  const panelAudit = document.getElementById("panel-audit");
  const viewTabs = [tabTable, tabDiagram, tabAudit].filter(Boolean);

  function activateViewTab(targetTab) {
    const viewMap = new Map([
      [tabTable, "table"],
      [tabDiagram, "diagram"],
      [tabAudit, "audit"],
    ]);
    state.activeView = viewMap.get(targetTab) || "table";

    for (const tab of viewTabs) {
      const selected = tab === targetTab;
      tab.setAttribute("aria-selected", String(selected));
      tab.toggleAttribute("focusgroupstart", selected);
    }
    panelTable.hidden = state.activeView !== "table";
    panelDiagram.hidden = state.activeView !== "diagram";
    if (panelAudit) panelAudit.hidden = state.activeView !== "audit";

    if (state.activeView === "diagram") {
      renderTopologyDiagram(true);
    } else if (state.activeView === "audit") {
      renderAuditPanel();
    }
  }

  viewTabs.forEach((tab, idx) => {
    tab.addEventListener("click", () => activateViewTab(tab));
    tab.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const next = viewTabs[(idx + (e.key === "ArrowRight" ? 1 : -1) + viewTabs.length) % viewTabs.length];
        next.focus();
        activateViewTab(next);
      } else if (e.key === "Home") {
        e.preventDefault();
        viewTabs[0].focus();
        activateViewTab(viewTabs[0]);
      } else if (e.key === "End") {
        e.preventDefault();
        viewTabs[viewTabs.length - 1].focus();
        activateViewTab(viewTabs[viewTabs.length - 1]);
      }
    });
  });

  // =========================================================================
  // Device & Bulk Enrichment Controls
  // =========================================================================
  const btnEnrichDevice = document.getElementById("btn-enrich-device");
  const btnEnrichAll = document.getElementById("btn-enrich-all");
  const btnEnrichAllLabel = document.getElementById("btn-enrich-all-label");

  if (btnEnrichDevice) {
    btnEnrichDevice.addEventListener("click", async () => {
      if (!state.selectedIp) return;
      const ip = state.selectedIp;
      state.enrichingIps.add(ip);
      renderDetails(state.devices.get(ip));
      try {
        const res = await fetch(`/api/devices/${encodeURIComponent(ip)}/enrich`, { method: "POST" });
        if (res.ok) {
          upsertDeviceUI(await res.json(), false);
        }
      } finally {
        state.enrichingIps.delete(ip);
        renderDetails(state.devices.get(ip));
      }
    });
  }

  if (btnEnrichAll) {
    btnEnrichAll.addEventListener("click", async () => {
      btnEnrichAll.disabled = true;
      btnEnrichAllLabel.textContent = t("enriching");
      scanStatusText.textContent = t("status_enriching_all");
      try {
        const res = await fetch("/api/enrich-all", { method: "POST" });
        if (res.ok) {
          const data = await res.json();
          scanStatusText.textContent = t("status_enriched_all", { n: data.enriched });
          await loadBootstrap();
        }
      } finally {
        btnEnrichAll.disabled = false;
        btnEnrichAllLabel.textContent = t("enrich");
      }
    });
  }

  // =========================================================================
  // Interactive Multi-Subnet SVG Topology Diagram (pan, zoom, click-to-inspect)
  // =========================================================================
  const topoSvg = document.getElementById("topology-svg");
  const canvasWrap = document.getElementById("diagram-canvas-wrap");
  const zoomLabel = document.getElementById("zoom-level");
  const btnZoomIn = document.getElementById("btn-zoom-in");
  const btnZoomOut = document.getElementById("btn-zoom-out");
  const btnZoomFit = document.getElementById("btn-zoom-fit");

  const cam = { x: 0, y: 0, scale: 1, contentW: 1100, contentH: 700 };
  let diagramTimer = null;

  function scheduleDiagramRender() {
    clearTimeout(diagramTimer);
    diagramTimer = setTimeout(() => renderTopologyDiagram(false), 120);
  }

  function applyCamera() {
    const g = topoSvg.querySelector("#topo-viewport");
    if (g) {
      g.setAttribute("transform", `translate(${cam.x.toFixed(1)}, ${cam.y.toFixed(1)}) scale(${cam.scale.toFixed(3)})`);
    }
    if (zoomLabel) zoomLabel.textContent = `${Math.round(cam.scale * 100)}%`;
  }

  function fitDiagram() {
    const rect = canvasWrap.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const pad = 28;
    const scaleX = (rect.width - pad * 2) / Math.max(1, cam.contentW);
    const scaleY = (rect.height - pad * 2) / Math.max(1, cam.contentH);
    cam.scale = Math.max(0.35, Math.min(1.15, Math.min(scaleX, scaleY)));
    cam.x = (rect.width - cam.contentW * cam.scale) / 2;
    cam.y = Math.max(16, (rect.height - cam.contentH * cam.scale) / 2);
    applyCamera();
  }

  function zoomBy(factor, cx = null, cy = null) {
    const rect = canvasWrap.getBoundingClientRect();
    const px = cx ?? rect.width / 2;
    const py = cy ?? rect.height / 2;
    const nextScale = Math.max(0.3, Math.min(2.4, cam.scale * factor));
    const ratio = nextScale / cam.scale;
    cam.x = px - (px - cam.x) * ratio;
    cam.y = py - (py - cam.y) * ratio;
    cam.scale = nextScale;
    applyCamera();
  }

  if (btnZoomIn) btnZoomIn.addEventListener("click", () => zoomBy(1.2));
  if (btnZoomOut) btnZoomOut.addEventListener("click", () => zoomBy(0.82));
  if (btnZoomFit) btnZoomFit.addEventListener("click", fitDiagram);

  // Pan & mousewheel zoom
  let dragging = false;
  let dragStart = { x: 0, y: 0, cx: 0, cy: 0 };

  if (canvasWrap) {
    canvasWrap.addEventListener("pointerdown", (e) => {
      if (e.target.closest(".topo-node")) return;
      dragging = true;
      canvasWrap.classList.add("dragging");
      dragStart = { x: e.clientX, y: e.clientY, cx: cam.x, cy: cam.y };
      canvasWrap.setPointerCapture(e.pointerId);
    });
    canvasWrap.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      cam.x = dragStart.cx + (e.clientX - dragStart.x);
      cam.y = dragStart.cy + (e.clientY - dragStart.y);
      applyCamera();
    });
    const endDrag = () => {
      dragging = false;
      canvasWrap.classList.remove("dragging");
    };
    canvasWrap.addEventListener("pointerup", endDrag);
    canvasWrap.addEventListener("pointercancel", endDrag);
    canvasWrap.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        const rect = canvasWrap.getBoundingClientRect();
        zoomBy(e.deltaY < 0 ? 1.1 : 0.9, e.clientX - rect.left, e.clientY - rect.top);
      },
      { passive: false }
    );
  }

  function highlightDiagramSelection(ip) {
    topoSvg.querySelectorAll(".topo-node").forEach((el) => {
      el.classList.toggle("selected", el.dataset.ip === ip);
    });
    topoSvg.querySelectorAll(".topo-edge[data-target-ip]").forEach((el) => {
      el.classList.toggle("highlighted", el.dataset.targetIp === ip);
    });
  }

  function truncate(str, max) {
    const s = String(str || "");
    return s.length > max ? `${s.slice(0, max - 1)}…` : s;
  }

  async function renderTopologyDiagram(autoFit = false) {
    let topo;
    try {
      const res = await fetch("/api/topology");
      topo = await res.json();
    } catch {
      return;
    }

    const subnets = (topo.subnets || []).filter(
      (s) => state.activeSubnetFilter === "all" || s.cidr === state.activeSubnetFilter
    );

    if (subnets.length === 0) {
      topoSvg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="var(--fg-muted)" font-size="14">${escapeHtml(t("diagram_no_subnets"))}</text>`;
      return;
    }

    const NODE_W = 218;
    const NODE_H = 82;
    const COL_GAP = 22;
    const ROW_GAP = 24;
    const ZONE_PAD = 26;
    const ZONE_GAP = 46;
    const TOP_INTERNET_Y = 22;
    const SUBNETS_TOP_Y = 160;

    // Pre-compute layout for each subnet cluster
    const clusters = subnets.map((sub) => {
      const filteredDevs = (sub.devices || []).filter((d) => matchesFilters(d));
      const cols = Math.max(2, Math.min(4, Math.ceil(Math.sqrt(Math.max(1, filteredDevs.length)))));
      const rows = Math.max(1, Math.ceil(filteredDevs.length / cols));
      const gridW = cols * NODE_W + (cols - 1) * COL_GAP;
      const zoneW = Math.max(400, gridW + ZONE_PAD * 2);
      const gwBlockH = 132;
      const gridH = filteredDevs.length > 0 ? rows * NODE_H + (rows - 1) * ROW_GAP : 44;
      const zoneH = 44 + gwBlockH + gridH + ZONE_PAD;
      return { sub, filteredDevs, cols, rows, zoneW, zoneH, x: 0, y: SUBNETS_TOP_Y };
    });

    const totalW =
      clusters.reduce((acc, c) => acc + c.zoneW, 0) + Math.max(0, clusters.length - 1) * ZONE_GAP + 80;
    const maxZoneH = Math.max(...clusters.map((c) => c.zoneH), 280);
    const totalH = SUBNETS_TOP_Y + maxZoneH + 54;

    let curX = 40;
    for (const c of clusters) {
      c.x = curX;
      curX += c.zoneW + ZONE_GAP;
    }

    cam.contentW = totalW;
    cam.contentH = totalH;

    const internetX = totalW / 2 - 110;
    const internetW = 220;
    const internetH = 68;
    const internetCx = internetX + internetW / 2;
    const internetBy = TOP_INTERNET_Y + internetH;

    const edgesSvg = [];
    const zonesSvg = [];
    const nodesSvg = [];
    const posByIp = new Map();
    const gwPosByCidr = new Map();

    // First pass: position zones, gateways, and illustrated device nodes
    for (const c of clusters) {
      const { sub, filteredDevs, cols, zoneW, zoneH, x, y } = c;
      const color = sub.color || "#2563eb";
      const gw = sub.gateway;
      const gwW = 248;
      const gwH = 84;
      const gwX = x + (zoneW - gwW) / 2;
      const gwY = y + 48;
      const gwCx = gwX + gwW / 2;
      const gwBy = gwY + gwH;
      gwPosByCidr.set(sub.cidr, { cx: gwCx, topY: gwY, botY: gwBy, color });
      if (gw && gw.ipv4) {
        posByIp.set(gw.ipv4, { cx: gwCx, cy: gwY + gwH / 2, topY: gwY, botY: gwBy });
      }

      zonesSvg.push(`
        <g>
          <rect class="topo-zone" x="${x}" y="${y}" width="${zoneW}" height="${zoneH}" rx="16" stroke="${escapeHtml(color)}"/>
          <circle cx="${x + 18}" cy="${y + 23}" r="5.5" fill="${escapeHtml(color)}"/>
          <text class="topo-zone-title" x="${x + 31}" y="${y + 27}">${escapeHtml(sub.name)}</text>
          <text class="topo-zone-sub" x="${x + zoneW - 16}" y="${y + 27}" text-anchor="end">${escapeHtml(sub.cidr)} · ${escapeHtml(t("diagram_active_ratio", { on: sub.online_count, tot: sub.total_count }))}</text>
        </g>
      `);

      // Render Gateway node with detailed router illustration
      if (gw) {
        const gwTitle = truncate(gw.custom_hostname || gw.identification || gw.vendor || I18N.typeLabel("router"), 21);
        const gwSub = gw.vendor ? truncate(gw.vendor, 22) : t("diagram_gateway_sub");
        const portsN = (gw.ports || []).length;
        const selectedCls = state.selectedIp === gw.ipv4 ? " selected" : "";
        nodesSvg.push(`
          <g class="topo-node gateway${selectedCls}" data-ip="${escapeHtml(gw.ipv4)}" data-virtual="${gw.virtual ? "1" : "0"}" transform="translate(${gwX}, ${gwY})">
            <rect class="topo-node-bg" width="${gwW}" height="${gwH}" rx="12" stroke="${escapeHtml(color)}"/>
            <rect class="topo-illus-frame" x="10" y="13" width="58" height="58" rx="10"/>
            <g transform="translate(15, 18)">${DEVICE_DRAWINGS.router}</g>
            <circle cx="${gwW - 14}" cy="15" r="4.8" fill="${gw.is_online ? "#22c55e" : "#ef4444"}"/>
            <text class="topo-node-title" x="78" y="29">${escapeHtml(gwTitle)}</text>
            <text class="topo-node-ip" x="78" y="47">${escapeHtml(gw.ipv4)}</text>
            <text class="topo-node-meta" x="78" y="64">${escapeHtml(gwSub)}</text>
            ${
              portsN > 0
                ? `<rect class="topo-ports-pill" x="${gwW - 44}" y="54" width="34" height="17" rx="8.5"/>
                   <text class="topo-ports-text" x="${gwW - 27}" y="66" text-anchor="middle">${portsN}p</text>`
                : ""
            }
          </g>
        `);
      }

      // Render child devices in grid with rich device drawings
      const gridTopY = gwBy + 44;
      const gridW = cols * NODE_W + (cols - 1) * COL_GAP;
      const gridStartX = x + (zoneW - gridW) / 2;

      if (filteredDevs.length === 0) {
        nodesSvg.push(
          `<text class="topo-node-meta" x="${x + zoneW / 2}" y="${gridTopY + 18}" text-anchor="middle">${escapeHtml(t("diagram_no_matches"))}</text>`
        );
      }

      filteredDevs.forEach((dev, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        const nx = gridStartX + col * (NODE_W + COL_GAP);
        const ny = gridTopY + row * (NODE_H + ROW_GAP);
        const ncx = nx + NODE_W / 2;
        posByIp.set(dev.ipv4, { cx: ncx, cy: ny + NODE_H / 2, topY: ny, botY: ny + NODE_H });

        const midY = gwBy + 20;
        const edgeCls = `topo-edge${dev.is_online ? "" : " offline"}${state.selectedIp === dev.ipv4 ? " highlighted" : ""}`;
        edgesSvg.push(
          `<path class="${edgeCls}" data-target-ip="${escapeHtml(dev.ipv4)}" d="M ${gwCx} ${gwBy} C ${gwCx} ${midY}, ${ncx} ${ny - 22}, ${ncx} ${ny}"/>`
        );

        const extra = dev.extra || {};
        const dtype = dev.device_type || "unknown";
        const primaryLabel = truncate(
          dev.custom_hostname || extra.model || dev.identification || extra.brand || dev.vendor || dev.ipv4,
          17
        );
        const secondaryLabel = truncate(
          dev.location || I18N.typeLabel(dtype) || dev.vendor,
          19
        );
        const portsN = (dev.ports || []).length;
        const selectedCls = state.selectedIp === dev.ipv4 ? " selected" : "";

        nodesSvg.push(`
          <g class="topo-node${selectedCls}" data-ip="${escapeHtml(dev.ipv4)}" transform="translate(${nx}, ${ny})">
            <rect class="topo-node-bg" width="${NODE_W}" height="${NODE_H}" rx="11"/>
            <rect class="topo-illus-frame" x="9" y="13" width="56" height="56" rx="10"/>
            <g transform="translate(13, 17)">${DEVICE_DRAWINGS[dtype] || DEVICE_DRAWINGS.unknown}</g>
            <circle cx="${NODE_W - 13}" cy="14" r="4.2" fill="${dev.is_online ? "#22c55e" : "#ef4444"}"/>
            <text class="topo-node-title" x="74" y="28">${escapeHtml(primaryLabel)}</text>
            <text class="topo-node-ip" x="74" y="46">${escapeHtml(dev.ipv4)}</text>
            <text class="topo-node-meta" x="74" y="63">${escapeHtml(secondaryLabel)}</text>
            ${
              portsN > 0
                ? `<rect class="topo-ports-pill" x="${NODE_W - 41}" y="53" width="32" height="17" rx="8.5"/>
                   <text class="topo-ports-text" x="${NODE_W - 25}" y="65" text-anchor="middle">${portsN}p</text>`
                : ""
            }
          </g>
        `);
      });
    }

    // Second pass: uplink edges (Internet -> Primary Router, and Cascaded Router link if detected!)
    for (const c of clusters) {
      const { sub } = c;
      const gwPos = gwPosByCidr.get(sub.cidr);
      if (!gwPos) continue;
      const casc = sub.cascaded_from;
      if (casc && posByIp.has(casc.wan_ip)) {
        const wanPos = posByIp.get(casc.wan_ip);
        const ctrlY = Math.min(wanPos.topY, gwPos.topY) - 52;
        edgesSvg.push(
          `<path class="topo-edge uplink cascaded" d="M ${wanPos.cx} ${wanPos.topY} C ${wanPos.cx} ${ctrlY}, ${gwPos.cx} ${ctrlY}, ${gwPos.cx} ${gwPos.topY}"/>`
        );
        const lx = (wanPos.cx + gwPos.cx) / 2;
        const ly = ctrlY + 10;
        edgesSvg.push(
          `<text class="topo-zone-sub" x="${lx}" y="${ly}" text-anchor="middle">${escapeHtml(t("diagram_cascade_label", { wan: casc.wan_ip, gw: sub.gateway?.ipv4 || "" }))}</text>`
        );
      } else {
        const midY = (internetBy + gwPos.topY) / 2;
        edgesSvg.push(
          `<path class="topo-edge uplink" d="M ${internetCx} ${internetBy} C ${internetCx} ${midY}, ${gwPos.cx} ${midY}, ${gwPos.cx} ${gwPos.topY}"/>`
        );
      }
    }

    // Illustrated Internet / WAN root node
    const internetNode = `
      <g class="topo-node" transform="translate(${internetX}, ${TOP_INTERNET_Y})">
        <rect class="topo-node-bg" width="${internetW}" height="${internetH}" rx="34" stroke="var(--accent)"/>
        <g transform="translate(14, 10)">${DEVICE_DRAWINGS.internet}</g>
        <text class="topo-node-title" x="72" y="30">${escapeHtml(t("diagram_internet"))}</text>
        <text class="topo-node-meta" x="72" y="48">${escapeHtml(t("diagram_networks_count", { n: subnets.length }))}</text>
      </g>
    `;

    topoSvg.innerHTML = `
      <g id="topo-viewport">
        ${zonesSvg.join("")}
        ${edgesSvg.join("")}
        ${internetNode}
        ${nodesSvg.join("")}
      </g>
    `;

    topoSvg.querySelectorAll(".topo-node[data-ip]").forEach((nodeEl) => {
      nodeEl.addEventListener("click", (e) => {
        e.stopPropagation();
        if (nodeEl.dataset.virtual === "1") return;
        const ip = nodeEl.dataset.ip;
        if (state.devices.has(ip)) {
          selectDevice(ip);
          if (detailsPane.classList.contains("collapsed")) {
            detailsPane.classList.remove("collapsed");
            btnToggleDetails.classList.add("active");
            btnToggleDetails.setAttribute("aria-pressed", "true");
          }
        }
      });
    });

    if (autoFit) {
      fitDiagram();
    } else {
      applyCamera();
    }
  }

  // =========================================================================
  // Network Architecture Audit & Recommendations Panel
  // =========================================================================
  const auditScoreArc = document.getElementById("audit-score-arc");
  const auditOverallScore = document.getElementById("audit-overall-score");
  const auditSubtitle = document.getElementById("audit-subtitle");
  const auditSubscores = document.getElementById("audit-subscores");
  const auditFindingsEl = document.getElementById("audit-findings");
  const auditIpPlanSection = document.getElementById("audit-ip-plan-section");
  const auditIpPlanBody = document.getElementById("audit-ip-plan-body");
  const btnRefreshAudit = document.getElementById("btn-refresh-audit");
  const auditCatFilters = document.getElementById("audit-cat-filters");

  let auditTimer = null;
  function scheduleAuditRender() {
    clearTimeout(auditTimer);
    auditTimer = setTimeout(renderAuditPanel, 150);
  }

  function scoreColor(val) {
    if (val >= 80) return "#22c55e";
    if (val >= 60) return "#f59e0b";
    return "#ef4444";
  }

  function paintAuditFindings() {
    if (!state.lastAudit || !auditFindingsEl) return;
    const all = state.lastAudit.findings || [];
    const filtered =
      state.auditCategory === "all"
        ? all
        : all.filter((f) => f.category === state.auditCategory);

    if (filtered.length === 0) {
      auditFindingsEl.innerHTML = `<p class="muted">${escapeHtml(t("audit_empty_cat"))}</p>`;
      return;
    }

    auditFindingsEl.innerHTML = filtered
      .map((f) => {
        const ipsHtml = (f.affected_ips || []).length
          ? `<div class="finding-ips">
              <span class="spec-label">${escapeHtml(t("audit_affected_devices"))}</span>
              ${f.affected_ips
                .map((ip) => {
                  const dev = state.devices.get(ip);
                  const lbl = dev && dev.custom_hostname ? `${ip} (${dev.custom_hostname})` : ip;
                  return `<button type="button" class="ip-chip" data-jump-ip="${escapeHtml(ip)}">${escapeHtml(lbl)}</button>`;
                })
                .join("")}
             </div>`
          : "";
        return `
          <article class="finding-card sev-${escapeHtml(f.severity)}">
            <div class="finding-head">
              <div class="finding-title-wrap">
                <span class="sev-badge ${escapeHtml(f.severity)}">${escapeHtml(t(`sev_${f.severity}`))}</span>
                <h3 class="finding-title">${escapeHtml(f.title)}</h3>
              </div>
              <span class="cat-tag">${escapeHtml(t(`cat_${f.category}`))}</span>
            </div>
            <p class="finding-desc">${escapeHtml(f.description)}</p>
            <div class="finding-rec"><strong>${escapeHtml(t("audit_recommendation_prefix"))}</strong> ${escapeHtml(f.recommendation)}</div>
            ${ipsHtml}
          </article>
        `;
      })
      .join("");

    auditFindingsEl.querySelectorAll("[data-jump-ip]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const ip = btn.dataset.jumpIp;
        if (state.devices.has(ip)) {
          selectDevice(ip);
          if (detailsPane.classList.contains("collapsed")) {
            detailsPane.classList.remove("collapsed");
            btnToggleDetails.classList.add("active");
            btnToggleDetails.setAttribute("aria-pressed", "true");
          }
        }
      });
    });
  }

  async function renderAuditPanel() {
    let data;
    try {
      const res = await fetch(`/api/recommendations?lang=${encodeURIComponent(I18N.getLang())}`);
      data = await res.json();
    } catch {
      return;
    }
    state.lastAudit = data;

    const overall = Number(data.overall_score || 0);
    const circ = 263.9;
    if (auditOverallScore) auditOverallScore.textContent = String(overall);
    if (auditScoreArc) {
      auditScoreArc.style.strokeDashoffset = String(circ * (1 - overall / 100));
      auditScoreArc.style.stroke = scoreColor(overall);
    }

    const sum = data.summary || {};
    if (auditSubtitle) {
      auditSubtitle.textContent = t("audit_summary_fmt", {
        tot: sum.total_devices || 0,
        subs: sum.active_subnets || 0,
        crit: sum.critical || 0,
        warn: sum.warning || 0,
        info: sum.info || 0,
      });
    }

    if (auditSubscores) {
      const sc = data.scores || {};
      auditSubscores.innerHTML = ["topology", "security", "performance", "organization"]
        .map((key) => {
          const v = Number(sc[key] || 0);
          return `
            <div class="subscore-item">
              <div class="subscore-top"><span>${escapeHtml(t(`cat_${key}`))}</span><span>${v}/100</span></div>
              <div class="subscore-bar"><div class="subscore-fill" style="width:${v}%;background:${scoreColor(v)}"></div></div>
            </div>
          `;
        })
        .join("");
    }

    paintAuditFindings();

    const plan = data.ip_plan || [];
    if (auditIpPlanSection && auditIpPlanBody) {
      auditIpPlanSection.hidden = plan.length === 0;
      auditIpPlanBody.innerHTML = plan
        .map(
          (row) => `
          <tr>
            <td class="mono">${escapeHtml(row.range)}</td>
            <td><strong>${escapeHtml(row.role)}</strong></td>
            <td>${escapeHtml(row.example)}</td>
          </tr>
        `
        )
        .join("");
    }
  }

  if (btnRefreshAudit) {
    btnRefreshAudit.addEventListener("click", renderAuditPanel);
  }

  if (auditCatFilters) {
    auditCatFilters.querySelectorAll("[data-audit-cat]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.auditCategory = btn.dataset.auditCat;
        auditCatFilters.querySelectorAll("[data-audit-cat]").forEach((b) => {
          b.setAttribute("aria-pressed", String(b === btn));
        });
        paintAuditFindings();
      });
    });
  }

  applyLanguage(I18N.getLang());
  loadBootstrap().then(connectEvents);
})();
