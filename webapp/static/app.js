/* red-alert — web reconnaissance console.
   Vanilla JavaScript, no build step, no dependencies. */
(function () {
  "use strict";

  var state = {
    view: "overview",
    job: null,          // the active recon job id
    jobResult: null,    // the job's result summary
    jobEvents: [],
    tables: [],
    stats: {},
    meta: {},
    recon: {},
    targets: [],        // every target that has been scanned
    dataTable: "",
    rows: {},           // table name -> rows
    tableInfo: {}       // table name -> {columns, rowCount, available}
  };

  var VIEWS = {
    overview: { title: "Overview", sub: "What the target is, and what it gives away." },
    surface: { title: "Paths & assets", sub: "Every path the target advertises, and what answered." },
    api: { title: "API surface", sub: "The addresses the application itself calls, read out of its own bundles — and what each one answered." },
    endpoints: { title: "API contract", sub: "The endpoint contract, from published specifications and from the routes the bundles declare." },
    data: { title: "Extracted data", sub: "The documents the target publishes, and what was extracted from them." },
    exposure: { title: "Exposure", sub: "Paths that answer without a session, or that should not be public." },
    leaks: { title: "Credentials", sub: "Credential-shaped strings found in the files the target serves. Masked, never printed in full." },
    information: { title: "Disclosures", sub: "What the served files say about the inside: internal hosts, configuration, source paths, and the notes developers left." },
    sources: { title: "Source maps", sub: "Original source recovered from published source maps." },
    vulnerabilities: { title: "Vulnerabilities", sub: "Exposure that was demonstrated, not merely observed: a cross-origin read, a file outside the web root, per-record data to anyone, an injectable parameter." },
    graph: { title: "Attack graph", sub: "The nodes connected to the target, and the routes from the front door to the things worth coming for." },
    cves: { title: "CVEs", sub: "Advisories the observed versions fall into. A version match is an inference, and it says what it needs besides." },
    agent: { title: "Exploit agent", sub: "A model plans the checks; the agent runs them against the target and reports what it found." },
    probes: { title: "Jailbreak probes", sub: "Every forced-disclosure probe that was sent, and whether the target held the line." },
    recovered: { title: "Recovered files", sub: "What the exposed artefacts actually contain: source from a published repository, members of a published archive, the tables of a published dump." },
    triage: { title: "Triage", sub: "The target's own security posture, as its headers describe it." },
    coverage: { title: "Coverage", sub: "What the scan looked at, and what it did not. Absence of a finding is not proof of absence." },
    audit: { title: "Audit", sub: "Every request the run made." },
    log: { title: "Run log", sub: "The run, step by step." }
  };

  var FIXED_TABLES = ["surface", "api", "exposure", "leaks", "information", "endpoints", "sources", "recovered", "vulnerabilities", "triage", "coverage", "audit"];

  // ------------------------------------------------------------------ utils

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        if (key === "class") node.className = attrs[key];
        else if (key === "html") node.innerHTML = attrs[key];
        else if (key === "text") node.textContent = attrs[key];
        else if (key.slice(0, 2) === "on") node.addEventListener(key.slice(2), attrs[key]);
        else if (attrs[key] !== null && attrs[key] !== undefined) node.setAttribute(key, attrs[key]);
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) return;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function num(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "number") {
      if (Number.isInteger(value)) return value.toLocaleString("en-US");
      return (Math.round(value * 10000) / 10000).toLocaleString("en-US");
    }
    var parsed = Number(value);
    if (!isNaN(parsed)) return num(parsed);
    return String(value);
  }

  function bytes(value) {
    var size = Number(value) || 0;
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
    return (size / (1024 * 1024)).toFixed(2) + " MB";
  }

  function seconds(value) {
    var number = Number(value) || 0;
    return (Math.round(number * 10) / 10).toFixed(1) + " s";
  }

  function clockOf(stamp) {
    if (!stamp) return "—";
    return new Date(stamp * 1000).toISOString().replace("T", " ").replace("Z", "");
  }

  function getJSON(url) {
    return fetch(url, { headers: { Accept: "application/json" } }).then(function (response) {
      if (!response.ok) throw new Error("HTTP " + response.status + " for " + url);
      return response.json();
    });
  }

  function postJSON(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok) throw new Error(payload.error || ("HTTP " + response.status));
        return payload;
      });
    });
  }

  function escapeHtml(value) {
    return String(value === null || value === undefined ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/'/g, "&#39;");
  }

  function jobQuery(extra) {
    var base = state.job ? "?job=" + encodeURIComponent(state.job) : "";
    return base + (extra ? (base ? "&" : "?") + extra : "");
  }

  function tableMeta(name) {
    for (var i = 0; i < state.tables.length; i += 1) {
      if (state.tables[i].name === name) return state.tables[i];
    }
    return null;
  }

  /** Load a table. Never rejects: a missing table is a state, not an error. */
  function loadTable(name) {
    if (state.tableInfo[name] && state.rows[name]) {
      return Promise.resolve(state.tableInfo[name]);
    }
    var meta = tableMeta(name) || {};
    return getJSON("/api/table/" + encodeURIComponent(name) + jobQuery("limit=3000"))
      .then(function (payload) {
        state.rows[name] = payload.rows || [];
        state.tableInfo[name] = {
          name: name,
          columns: payload.columns || meta.columns || [],
          rowCount: payload.total !== undefined ? payload.total : (meta.row_count || 0),
          available: true
        };
        return state.tableInfo[name];
      })
      .catch(function () {
        state.rows[name] = [];
        state.tableInfo[name] = {
          name: name,
          columns: meta.columns || [],
          rowCount: meta.row_count || 0,
          available: false
        };
        return state.tableInfo[name];
      });
  }

  // ------------------------------------------------------------------ shell

  function setView(name) {
    if (!VIEWS[name]) return;
    state.view = name;
    applyViewMeta(name);
    try {
      if (window.location.hash.slice(1) !== name) {
        window.history.replaceState(null, "", "#" + name);
      }
    } catch (error) {
      /* a sandboxed frame may refuse history writes; the view still changes */
    }
    render();
  }

  function applyViewMeta(name) {
    var meta = VIEWS[name] || VIEWS.overview;
    var title = document.getElementById("view-title");
    var subtitle = document.getElementById("view-subtitle");
    if (title) title.textContent = meta.title;
    if (subtitle) subtitle.textContent = meta.sub;
    var items = document.querySelectorAll(".nav-item");
    for (var i = 0; i < items.length; i += 1) {
      items[i].classList.toggle("active", items[i].dataset.view === name);
    }
    openSectionFor(name);
  }

  /** Open the section that holds the active view, and fold the others away.

   The sidebar is long enough without every section open at once, so the
   sections behave like an accordion: whichever one the active view lives in
   is open, the rest are closed.
   */
  function openSectionFor(name) {
    var sections = document.querySelectorAll(".nav-section");
    for (var i = 0; i < sections.length; i += 1) {
      if (sections[i].id === "target-section") continue;
      var match = sections[i].querySelector('.nav-item[data-view="' + name + '"]');
      sections[i].open = !!match;
    }
  }

  function setPill(tone, label) {
    var pill = document.getElementById("status-pill");
    if (!pill) return;
    pill.setAttribute("data-state", tone);
    pill.textContent = label;
  }

  function render() {
    var content = document.getElementById("content");
    if (!content) return;
    content.innerHTML = "";
    var items = document.querySelectorAll(".nav-item");
    for (var i = 0; i < items.length; i += 1) {
      items[i].classList.toggle("active", items[i].dataset.view === state.view);
    }
    var builder = {
      overview: viewOverview,
      surface: viewSurface,
      api: viewApi,
      endpoints: viewEndpoints,
      exposure: viewExposure,
      leaks: viewLeaks,
      information: viewInformation,
      sources: viewSources,
      recovered: viewRecovered,
      vulnerabilities: viewVulnerabilities,
      graph: viewGraph,
      cves: viewCves,
      agent: viewAgent,
      probes: viewProbes,
      data: viewData,
      triage: viewTriage,
      coverage: viewCoverage,
      audit: viewAudit,
      log: viewLog
    }[state.view] || viewOverview;
    try {
      content.appendChild(builder());
    } catch (error) {
      content.appendChild(failureCard(error));
    }
  }

  // ------------------------------------------------------------- target list

  /** Every target that has been scanned, newest first. */
  function loadTargets() {
    return getJSON("/api/recon/targets").then(function (payload) {
      state.targets = payload.targets || [];
      renderTargets();
      return state.targets;
    }).catch(function () {
      state.targets = [];
      renderTargets();
      return state.targets;
    });
  }

  function renderTargets() {
    var host = document.getElementById("target-list");
    var count = document.getElementById("target-count");
    if (!host) return;
    host.innerHTML = "";
    if (count) count.textContent = String(state.targets.length);
    if (!state.targets.length) {
      host.appendChild(el("div", {
        class: "nav-empty",
        text: "No target has been scanned yet. Type a URL above and press Enter."
      }));
      return;
    }
    state.targets.forEach(function (target) {
      host.appendChild(targetButton(target));
    });
  }

  function targetButton(target) {
    var url = target.target || target.url || "";
    var host = url;
    var path = "";
    try {
      var parsed = new URL(url);
      host = parsed.host;
      path = (parsed.pathname || "") + (parsed.search || "");
    } catch (error) {
      /* an address that will not parse is shown as it came in */
    }
    var button = el("button", {
      class: "target-item" + (state.job === target.id ? " active" : ""),
      title: url,
      type: "button"
    });
    button.appendChild(el("span", { class: "target-host", text: host || url }));
    if (path && path !== "/") {
      button.appendChild(el("span", { class: "target-path", text: path }));
    }
    var meta = el("span", { class: "target-meta" });
    if (target.vulnerabilities) {
      meta.appendChild(el("span", { class: "target-badge bad", text: target.vulnerabilities + " proven" }));
    } else if (target.exposed) {
      meta.appendChild(el("span", { class: "target-badge warn", text: target.exposed + " exposed" }));
    } else {
      meta.appendChild(el("span", { class: "target-badge ok", text: "no exposure" }));
    }
    if (target.endpoints) {
      meta.appendChild(el("span", { class: "target-badge", text: target.endpoints + " paths" }));
    }
    meta.appendChild(el("span", { class: "target-badge", text: clockOf(target.started_at) }));
    button.appendChild(meta);
    button.addEventListener("click", function () { openTarget(target.id); });
    return button;
  }

  /** Open a scanned target: load its dataset and show its overview. */
  function openTarget(jobId) {
    state.rows = {};
    state.tableInfo = {};
    attachJob(jobId, false);
    setView("overview");
    renderTargets();
  }

  // ---------------------------------------------------------------- widgets

  function failureCard(error) {
    var node = el("div", { class: "card" });
    node.appendChild(el("h3", {}, [el("span", { text: "This view could not be rendered" })]));
    node.appendChild(el("div", { class: "hint", text: String(error && error.message ? error.message : error) }));
    return node;
  }

  function kpi(value, label, tone) {
    var card = el("div", { class: "card" });
    card.appendChild(el("div", { class: "kpi-value" + (tone ? " kpi-" + tone : ""), text: value }));
    card.appendChild(el("div", { class: "kpi-label", text: label }));
    return card;
  }

  function card(title, meta, children) {
    var node = el("div", { class: "card" });
    var head = el("h3");
    head.appendChild(el("span", { text: title }));
    if (meta) head.appendChild(el("em", { text: meta }));
    node.appendChild(head);
    (children || []).forEach(function (child) { node.appendChild(child); });
    return node;
  }

  function summaryCard(text, meta) {
    var node = el("div", { class: "card", style: "margin-bottom:14px" });
    node.appendChild(el("div", { class: "summary-text", text: text }));
    if (meta) node.appendChild(el("div", { class: "hint", text: meta }));
    return node;
  }

  function emptySection(title, text) {
    var node = el("div", { class: "card" });
    node.appendChild(el("h3", {}, [el("span", { text: title })]));
    node.appendChild(el("div", { class: "hint", text: text }));
    return node;
  }

  /** The page every view shows when there is nothing to show yet. */
  function noResultsYet(title, what) {
    var node = el("div", { class: "card" });
    node.appendChild(el("h3", {}, [el("span", { text: title })]));
    node.appendChild(el("div", { class: "hint", text:
      "No scan has been run in this session yet, so there is nothing to show. " +
      "Type a target URL in the scan bar above, press Enter, and the recon will fill this page in."
    }));
    node.appendChild(el("div", { class: "hint", style: "margin-top:10px", text: what }));
    return node;
  }

  function tableElement(columns, rows, options) {
    options = options || {};
    var wrap = el("div", { class: "table-wrap" });
    var table = el("table");
    var thead = el("thead");
    var headRow = el("tr");
    columns.forEach(function (column) {
      var th = el("th", { class: options.sortable === false ? "" : "sortable" });
      th.appendChild(el("span", { text: column.label !== undefined ? column.label : column.key }));
      if (options.sortable !== false) {
        th.addEventListener("click", function () { sortTable(table, column.key); });
      }
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el("tbody");
    rows.forEach(function (row) {
      var tr = el("tr");
      columns.forEach(function (column) {
        var value = row[column.key];
        var classes = [];
        if (column.num) classes.push("num");
        if (column.name) classes.push("name");
        if (column.mono) classes.push("mono");
        var td = el("td", { class: classes.join(" ") });
        if (column.render) td.innerHTML = column.render(value, row);
        else td.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function sortTable(table, key) {
    var headCells = table.querySelectorAll("thead th");
    var columnIndex = -1;
    headCells.forEach(function (cell, position) {
      if (cell.querySelector("span").textContent === key) columnIndex = position;
    });
    if (columnIndex < 0) return;
    var tbody = table.querySelector("tbody");
    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
    var ascending = table.getAttribute("data-sort") !== key;
    table.setAttribute("data-sort", ascending ? key : "");
    rows.sort(function (a, b) {
      var left = a.children[columnIndex].textContent;
      var right = b.children[columnIndex].textContent;
      var ln = Number(String(left).replace(/[^0-9.\-]/g, ""));
      var rn = Number(String(right).replace(/[^0-9.\-]/g, ""));
      var lv = isNaN(ln) ? left.toLowerCase() : ln;
      var rv = isNaN(rn) ? right.toLowerCase() : rn;
      if (lv < rv) return ascending ? -1 : 1;
      if (lv > rv) return ascending ? 1 : -1;
      return 0;
    });
    rows.forEach(function (row) { tbody.appendChild(row); });
  }

  function barChart(rows, options) {
    options = options || {};
    var max = rows.reduce(function (acc, row) { return Math.max(acc, row.value); }, 0) || 1;
    var wrap = el("div", { class: "bars" });
    if (!rows.length) {
      wrap.appendChild(el("div", { class: "hint", text: "nothing to show" }));
      return wrap;
    }
    rows.forEach(function (row) {
      var line = el("div", { class: "bar-row" });
      line.appendChild(el("div", { class: "bar-label", text: row.label, title: row.label }));
      var track = el("div", { class: "bar-track" });
      var fill = el("div", { class: "bar-fill" + (row.tone ? " " + row.tone : "") });
      fill.style.width = Math.max(1.5, (row.value / max) * 100) + "%";
      track.appendChild(fill);
      line.appendChild(track);
      line.appendChild(el("div", { class: "bar-value", text: options.format ? options.format(row.value) : num(row.value) }));
      wrap.appendChild(line);
    });
    return wrap;
  }

  function countBy(rows, key) {
    var counts = {};
    rows.forEach(function (row) {
      var value = String(row[key] === undefined || row[key] === "" ? "—" : row[key]);
      counts[value] = (counts[value] || 0) + 1;
    });
    return counts;
  }

  function searchBox(placeholder, onInput) {
    var input = el("input", { class: "input", type: "search", placeholder: placeholder });
    input.addEventListener("input", function () { onInput(input.value); });
    return input;
  }

  function flagList(value) {
    var text = String(value || "");
    if (!text) return "—";
    return text.split(", ").map(function (flag) {
      var tone = /exposed|reachable without/.test(flag) ? "bad"
        : /credential|sensitive|backup|archive|source map/.test(flag) ? "warn"
        : /off-origin/.test(flag) ? "info" : "ok";
      return '<span class="tag ' + tone + '">' + escapeHtml(flag) + "</span>";
    }).join(" ");
  }

  // ----------------------------------------------------------------- views

  function hasScan() {
    return state.tables.length > 0 || !!state.job;
  }

  function expiredScan() {
    return state.job === null && state.jobAvailable === false;
  }

  function viewOverview() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "The overview summarises one scan: the target's identity, what it exposes, what it " +
            "discloses, and how much data it publishes."));
      return fragment;
    }
    var recon = state.recon || {};
    var result = state.jobResult || {};

    var kpis = el("div", { class: "grid grid-kpi" });
    kpis.appendChild(kpi(num(recon.endpoints), "paths & assets", "accent"));
    kpis.appendChild(kpi(num(result.exposed), "exposed files", result.exposed ? "bad" : ""));
    kpis.appendChild(kpi(num(result.leaks), "credentials", result.leaks ? "bad" : ""));
    kpis.appendChild(kpi(num(result.information), "disclosures", result.information ? "warn" : ""));
    kpis.appendChild(kpi(num(result.recovered), "files recovered", result.recovered ? "warn" : ""));
    kpis.appendChild(kpi(num(result.vulnerabilities), "proven exposures", result.vulnerabilities ? "bad" : ""));
    kpis.appendChild(kpi(num(result.api_endpoints), "API endpoints", result.api_endpoints ? "accent" : ""));
    kpis.appendChild(kpi(num(result.total_rows), "rows extracted"));
    kpis.appendChild(kpi(num(recon.requests), "requests made"));
    fragment.appendChild(kpis);

    var identity = el("div", { class: "grid grid-2", style: "margin-top:16px" });
    var info = el("div", {});
    info.appendChild(el("div", { class: "kpi-label", text: "target" }));
    info.appendChild(el("div", { class: "kpi-value", style: "font-size:15px", text: recon.target || state.meta.target || "—" }));
    info.appendChild(el("div", { class: "section-title", text: "identity" }));
    var identityList = el("div", { class: "kv" });
    [["Title", recon.title], ["Server", recon.server], ["Content type", recon.content_type],
     ["Technologies", (recon.technologies || []).join(", ")],
     ["JavaScript globals", (recon.globals || []).join(", ")],
     ["Scripts read", (recon.scripts || []).length],
     ["Endpoint candidates", recon.candidates],
     ["Sibling hosts", (recon.subdomains || []).join(", ")],
     ["Catch-all responses", recon.catch_all],
     ["Duration", seconds(result.duration_seconds)]]
      .forEach(function (pair) {
        if (!pair[1]) return;
        identityList.appendChild(el("dt", { text: pair[0] }));
        identityList.appendChild(el("dd", { text: String(pair[1]) }));
      });
    info.appendChild(identityList);
    identity.appendChild(card("Target", "as the scan found it", [info]));

    var warningsHost = el("div", {});
    var warnings = state.meta.warnings || [];
    if (warnings.length) {
      warnings.forEach(function (warning) {
        warningsHost.appendChild(el("div", { class: "banner", text: warning }));
      });
    } else {
      warningsHost.appendChild(el("div", { class: "hint", text: "No warnings were raised during the run." }));
    }
    identity.appendChild(card("Warnings", "", [warningsHost]));
    fragment.appendChild(identity);

    var charts = el("div", { class: "grid grid-2", style: "margin-top:16px" });
    var surfaceHost = el("div", { class: "bars" });
    charts.appendChild(card("Paths by kind", "what the target advertises", [surfaceHost]));
    var triageHost = el("div", { class: "bars" });
    charts.appendChild(card("Triage", "checks by verdict", [triageHost]));
    var disclosureHost = el("div", { class: "bars" });
    charts.appendChild(card("Disclosures by kind", "what the files give away", [disclosureHost]));
    fragment.appendChild(charts);

    var dataHost = el("div", {});
    charts.appendChild(card("Published data", "documents extracted", [dataHost]));
    fragment.appendChild(charts);

    Promise.all([loadTable("surface"), loadTable("triage"), loadTable("information")]).then(function (loaded) {
      var surfaceRows = state.rows.surface || [];
      var triageRows = state.rows.triage || [];
      var informationRows = state.rows.information || [];

      var kinds = countBy(surfaceRows, "kind");
      surfaceHost.innerHTML = "";
      surfaceHost.appendChild(barChart(
        Object.keys(kinds).map(function (key) { return { label: key, value: kinds[key] }; })
          .sort(function (a, b) { return b.value - a.value; })
      ));

      var verdicts = countBy(triageRows, "status");
      triageHost.innerHTML = "";
      triageHost.appendChild(barChart(
        Object.keys(verdicts).map(function (key) {
          return { label: key, value: verdicts[key], tone: key === "fail" ? "bad" : (key === "warn" ? "warn" : "") };
        })
      ));

      var disclosures = countBy(informationRows, "kind");
      disclosureHost.innerHTML = "";
      disclosureHost.appendChild(barChart(
        Object.keys(disclosures).map(function (key) {
          return { label: key, value: disclosures[key], tone: key === "critical" || key === "high" ? "bad" : "warn" };
        })
      ));

      var dataTables = state.tables.filter(function (item) {
        return FIXED_TABLES.indexOf(item.name) < 0;
      });
      dataHost.innerHTML = "";
      if (!dataTables.length) {
        dataHost.appendChild(el("div", { class: "hint", text: "no data document was extracted" }));
        return;
      }
      var bars = el("div", { class: "bars" });
      dataTables.slice().sort(function (a, b) { return b.row_count - a.row_count; }).forEach(function (item) {
        var line = el("div", { class: "bar-row" });
        line.appendChild(el("div", { class: "bar-label", text: item.name, title: item.name }));
        var track = el("div", { class: "bar-track" });
        var fill = el("div", { class: "bar-fill" });
        fill.style.width = Math.max(1.5, (item.row_count / (dataTables[0].row_count || 1)) * 100) + "%";
        track.appendChild(fill);
        line.appendChild(track);
        line.appendChild(el("div", { class: "bar-value", text: num(item.row_count) }));
        bars.appendChild(line);
      });
      dataHost.appendChild(bars);
    });

    return fragment;
  }

  function surfaceView(kind) {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page lists every path the target advertises, with the status, the size, and the " +
            "flags the scan assigned to it."));
      return fragment;
    }
    var toolbar = el("div", { class: "toolbar" });
    var count = el("span", { class: "hint" });
    toolbar.appendChild(searchBox("Filter by path, flag, or note…", function (value) { draw(value); }));
    toolbar.appendChild(count);
    fragment.appendChild(toolbar);

    var host = el("div", {});
    fragment.appendChild(host);

    loadTable(kind).then(function (info) {
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "The run in this session did not produce a '" + kind + "' table. Scan a target and the " +
          "page will fill in."));
        return;
      }
      var rows = state.rows[kind] || [];
      if (!rows.length) {
        host.appendChild(emptySection("Nothing was recorded",
          "The scan did not record any row for this section. That is a bounded negative: the scan " +
          "looked at the documents listed under Paths & assets, and no others."));
        return;
      }
      function draw(needle) {
        var lowered = (needle || "").toLowerCase();
        var filtered = rows.filter(function (row) {
          if (!lowered) return true;
          return Object.keys(row).some(function (key) {
            return String(row[key] === undefined ? "" : row[key]).toLowerCase().indexOf(lowered) >= 0;
          });
        });
        count.textContent = filtered.length + " of " + rows.length;
        host.innerHTML = "";
        host.appendChild(summaryCard(
          rows.length + " path(s) recorded.",
          kind === "exposure"
            ? "Everything here answered without a session, looked like a protected path, or was a " +
              "probe the operator asked for — found or not."
            : "Every path the target advertises, with what answered and how big it was."
        ));
        host.appendChild(tableElement(
          [
            { key: "path", label: "path", name: true, mono: true },
            { key: "kind", label: "kind" },
            { key: "status", label: "status", num: true },
            { key: "content_type", label: "content type" },
            { key: "bytes", label: "size", num: true, render: function (v) { return bytes(v); } },
            { key: "flags", label: "flags", render: function (v) { return flagList(v); } },
            { key: "note", label: "note" }
          ],
          filtered
        ));
      }
      draw("");
    });

    return fragment;
  }

  function viewSurface() { return surfaceView("surface"); }
  function viewExposure() { return surfaceView("exposure"); }

  function viewApi() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet("Nothing scanned yet",
        "This page holds the addresses the application calls for itself: the API root it builds " +
        "its paths from, the endpoints it names, and what each one answered — data, a refusal, " +
        "or nothing."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("api").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.api || [];
      if (!rows.length) {
        host.appendChild(emptySection("No API was found",
          "The scan read the bundles and the module graph and found no address the application " +
          "calls. That is a bounded negative, scoped to the modules that were read. If the target " +
          "is a static site with no JavaScript, there is no API to find — and the Coverage page " +
          "says how many bundles were read."));
        return;
      }
      var kinds = countBy(rows, "kind");
      var withData = rows.filter(function (row) { return row.kind === "api data"; }).length;
      host.appendChild(summaryCard(
        rows.length + " address(es) the application calls; " + withData + " answered with data.",
        "The API root, the endpoints, the off-origin hosts, and the status of each."
      ));
      host.appendChild(tableElement(
        [
          { key: "kind", label: "kind", name: true, render: function (v) {
              var tone = v === "api data" ? "ok" : (v === "off-origin API" ? "warn" : "info");
              return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
            } },
          { key: "url", label: "url", mono: true },
          { key: "origin", label: "origin" },
          { key: "source", label: "found in", mono: true },
          { key: "note", label: "answer" }
        ],
        rows
      ));
    });
    return fragment;
  }

  function viewEndpoints() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page shows the endpoint contract recovered from published specifications and from " +
        "the routes the bundles declare."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("endpoints").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.endpoints || [];
      if (!rows.length) {
        host.appendChild(emptySection("No API contract was recovered",
          "No OpenAPI, Swagger, GraphQL schema, or protobuf definition was published, and no " +
          "route was declared in the bundles that were read. That is a bounded negative: the " +
          "scan covered the documents listed under Paths & assets, and no others. The API " +
          "surface page lists the addresses the application does call."));
        return;
      }
      var kinds = countBy(rows, "source");
      host.appendChild(summaryCard(
        rows.length + " endpoint(s) recovered from " + Object.keys(kinds).length + " source(s).",
        "A published specification hands over the backend contract, including the paths a " +
        "client never calls; the derived routes are the addresses the bundles declare."
      ));
      host.appendChild(tableElement(
        [
          { key: "method", label: "method", name: true },
          { key: "path", label: "path", mono: true },
          { key: "source", label: "source", mono: true },
          { key: "summary", label: "summary" },
          { key: "auth", label: "auth" },
          { key: "parameters", label: "parameters" }
        ],
        rows,
        { sortable: false }
      ));
    });
    return fragment;
  }

  function viewLeaks() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page lists the credential-shaped strings found in the files the target serves. " +
        "The values are masked: they never enter the dataset, the log, or the report."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("leaks").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.leaks || [];
      if (!rows.length) {
        host.appendChild(emptySection("No credential-shaped strings found",
          "The pattern set was applied to every document the scan read. That is a bounded " +
          "negative, not a proof: the scan covered the files listed under Paths & assets, and " +
          "no others."));
        return;
      }
      host.appendChild(summaryCard(
        rows.length + " credential-shaped string(s) found.",
        "Reported by kind and location. The value itself is masked."
      ));
      host.appendChild(tableElement(
        [
          { key: "severity", label: "severity", render: function (v) {
              var tone = v === "critical" || v === "high" ? "bad" : "warn";
              return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
            } },
          { key: "kind", label: "kind", name: true },
          { key: "source", label: "source", mono: true },
          { key: "location", label: "location" },
          { key: "preview", label: "preview (masked)", mono: true },
          { key: "digest", label: "digest", mono: true },
          { key: "note", label: "note" }
        ],
        rows
      ));
    });
    return fragment;
  }

  function viewInformation() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page lists what the served files disclose about the inside: internal hosts, " +
        "configuration values, source paths, exposed files, and the notes developers left."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("information").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.information || [];
      if (!rows.length) {
        host.appendChild(emptySection("Nothing was disclosed",
          "The files the scan read named no internal host, no configuration value, and no source " +
          "path. That is a bounded negative, scoped to the documents that were read."));
        return;
      }
      var kinds = countBy(rows, "kind");
      host.appendChild(summaryCard(
        rows.length + " disclosure(s) across " + Object.keys(kinds).length + " kind(s).",
        "Internal hosts, configuration values, source paths, exposed files, and embedded state."
      ));
      var toolbar = el("div", { class: "toolbar" });
      var select = el("select", { class: "input" });
      select.appendChild(el("option", { value: "", text: "All kinds (" + rows.length + ")" }));
      Object.keys(kinds).sort().forEach(function (kind) {
        select.appendChild(el("option", { value: kind, text: kind + " (" + kinds[kind] + ")" }));
      });
      toolbar.appendChild(select);
      var count = el("span", { class: "hint" });
      toolbar.appendChild(count);
      host.appendChild(toolbar);

      var table = el("div", {});
      host.appendChild(table);
      function draw() {
        var selected = select.value;
        var filtered = selected ? rows.filter(function (row) { return row.kind === selected; }) : rows;
        count.textContent = filtered.length + " of " + rows.length;
        table.innerHTML = "";
        table.appendChild(tableElement(
          [
            { key: "kind", label: "kind", name: true },
            { key: "value", label: "value", mono: true },
            { key: "source", label: "source", mono: true },
            { key: "severity", label: "severity", render: function (v) {
                var tone = v === "critical" || v === "high" ? "bad" : (v === "medium" ? "warn" : "info");
                return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
              } },
            { key: "note", label: "note" }
          ],
          filtered
        ));
      }
      select.addEventListener("change", draw);
      draw();
    });
    return fragment;
  }

  function viewSources() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page lists the original source files that a published source map restores."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("sources").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.sources || [];
      if (!rows.length) {
        host.appendChild(emptySection("No source map was published",
          "No bundle referenced a sourceMappingURL, or the map was not reachable. When a bundle " +
          "does publish one, it restores the application's own file names — and sometimes the " +
          "original source text."));
        return;
      }
      host.appendChild(summaryCard(
        rows.length + " source file(s) named by published source maps.",
        "The original file names of the application's own source tree."
      ));
      host.appendChild(tableElement(
        [
          { key: "source", label: "file", mono: true, name: true },
          { key: "kind", label: "kind" },
          { key: "size", label: "size", num: true },
          { key: "note", label: "note" }
        ],
        rows
      ));
    });
    return fragment;
  }

  function viewRecovered() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet("Nothing scanned yet",
        "This page holds the files recovered from artefacts the target had already exposed: " +
        "the source tree behind a published repository, the members of a published archive, " +
        "the tables of a published database dump."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("recovered").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.recovered || [];
      if (!rows.length) {
        host.appendChild(emptySection("Nothing was recovered",
          "No exposed artefact held recoverable content: no published repository, no archive, " +
          "no dump. That is a bounded negative, scoped to the artefacts the scan probed."));
        return;
      }
      var origins = countBy(rows, "origin");
      host.appendChild(summaryCard(
        rows.length + " file(s) recovered from " + Object.keys(origins).length + " exposed artefact(s).",
        "The files are read, never executed. A credential inside one is masked before it is shown."
      ));
      host.appendChild(tableElement(
        [
          { key: "path", label: "file", mono: true, name: true },
          { key: "origin", label: "recovered from", mono: true },
          { key: "kind", label: "kind" },
          { key: "size", label: "size", num: true, render: function (v) { return bytes(v); } },
          { key: "secrets", label: "holds a credential", render: function (v) {
              return v ? '<span class="tag bad">masked</span>' : "—";
            } },
          { key: "preview", label: "preview", mono: true, render: function (v) {
              return '<span class="truncate" style="max-width:420px;display:inline-block" title="' +
                escapeAttr(v) + '">' + escapeHtml(v) + "</span>";
            } }
        ],
        rows
      ));
    });
    return fragment;
  }

  function viewVulnerabilities() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet("Nothing scanned yet",
        "This page holds the exposures the scan demonstrated: a cross-origin read that a " +
        "foreign page can make, a file read from outside the web root, per-record data served " +
        "without a session, an injectable parameter, a stack trace, an open redirect."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("vulnerabilities").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.vulnerabilities || [];
      if (!rows.length) {
        host.appendChild(emptySection("Nothing was demonstrated",
          "The active checks ran and did not prove an exposure. That is a bounded negative: the " +
          "checks covered the endpoints and paths listed under Paths & assets, and no others."));
        return;
      }
      var severities = countBy(rows, "severity");
      host.appendChild(summaryCard(
        rows.length + " demonstrated exposure(s): "
        + Object.keys(severities).map(function (key) { return severities[key] + " " + key; }).join(", ") + ".",
        "Each one carries the request that proved it and the response that came back."
      ));
      host.appendChild(tableElement(
        [
          { key: "severity", label: "severity", render: function (v) {
              var tone = v === "critical" ? "bad" : (v === "high" ? "warn" : "info");
              return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
            } },
          { key: "title", label: "finding", name: true },
          { key: "endpoint", label: "endpoint", mono: true },
          { key: "evidence", label: "evidence", mono: true, render: function (v) {
              return '<span class="truncate" style="max-width:420px;display:inline-block" title="' +
                escapeAttr(v) + '">' + escapeHtml(v) + "</span>";
            } },
          { key: "impact", label: "impact" }
        ],
        rows
      ));
    });
    return fragment;
  }

  // ------------------------------------------------------------ attack graph

  var GRAPH_COLUMNS = {
    origin: 0, host: 1, path: 2, contract: 3, data: 3, source: 3,
    credential: 4, disclosure: 4, vulnerability: 4, cve: 4, probe: 4
  };

  var GRAPH_KIND_LABELS = {
    origin: "target", path: "path", host: "host", contract: "contract", data: "published data",
    source: "source", credential: "credential", disclosure: "disclosure",
    vulnerability: "demonstrated", cve: "advisory", probe: "probe"
  };

  var GRAPH_KIND_COLORS = {
    origin: "#ff5a5f", path: "#5aa9ff", host: "#9b8cff", contract: "#6fd3c0", data: "#f0b429",
    source: "#8fd18f", credential: "#ff5a5f", disclosure: "#ffb35a", vulnerability: "#ff5a5f",
    cve: "#ff7ac0", probe: "#c58cff"
  };

  var SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function severityRank(value) {
    return SEVERITY_RANK[value] === undefined ? 5 : SEVERITY_RANK[value];
  }

  function svgEl(tag, attrs) {
    var node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.keys(attrs || {}).forEach(function (key) { node.setAttribute(key, attrs[key]); });
    return node;
  }

  function layoutGraph(graph) {
    var columns = {};
    (graph.nodes || []).forEach(function (node) {
      var index = GRAPH_COLUMNS[node.kind] === undefined ? 3 : GRAPH_COLUMNS[node.kind];
      if (!columns[index]) columns[index] = [];
      columns[index].push(node);
    });
    var positions = {};
    var rows = 0;
    Object.keys(columns).forEach(function (index) {
      var list = columns[index];
      list.sort(function (left, right) {
        var bySeverity = severityRank(left.severity) - severityRank(right.severity);
        if (bySeverity !== 0) return bySeverity;
        return String(left.label).localeCompare(String(right.label));
      });
      list.forEach(function (node, position) {
        var depth = 0;
        if (node.kind === "host") {
          depth = Number((node.meta || {}).depth || 0);
        }
        positions[node.id] = {
          x: 80 + Number(index) * 250 + depth * 22,
          y: 46 + position * 40,
          node: node
        };
      });
      rows = Math.max(rows, list.length);
    });
    var columnCount = Object.keys(columns).length || 1;
    return {
      positions: positions,
      width: 120 + columnCount * 250,
      height: 70 + rows * 40
    };
  }

  function drawGraphSVG(graph, layout, onSelect) {
    var svg = svgEl("svg", {
      class: "graph-svg",
      viewBox: "0 0 " + layout.width + " " + layout.height,
      preserveAspectRatio: "xMinYMin meet"
    });
    var edgeLayer = svgEl("g", { class: "graph-edges" });
    var nodeLayer = svgEl("g", { class: "graph-nodes" });

    (graph.edges || []).forEach(function (edge) {
      var from = layout.positions[edge.source];
      var to = layout.positions[edge.target];
      if (!from || !to) return;
      var mid = (from.x + to.x) / 2;
      var line = svgEl("path", {
        d: "M " + from.x + " " + from.y + " C " + mid + " " + from.y + ", " + mid + " " + to.y
           + ", " + to.x + " " + to.y,
        class: "graph-edge edge-" + edge.kind,
        "data-source": edge.source,
        "data-target": edge.target
      });
      line.appendChild(svgEl("title", {}));
      line.lastChild.textContent = edge.label || edge.kind;
      edgeLayer.appendChild(line);
    });

    (graph.nodes || []).forEach(function (node) {
      var position = layout.positions[node.id];
      if (!position) return;
      var group = svgEl("g", {
        class: "graph-node kind-" + node.kind + " sev-" + (node.severity || "info"),
        "data-id": node.id
      });
      group.appendChild(svgEl("circle", {
        cx: position.x, cy: position.y, r: 7,
        fill: GRAPH_KIND_COLORS[node.kind] || "#8892a6"
      }));
      var label = svgEl("text", { x: position.x + 12, y: position.y + 4, class: "graph-label" });
      label.textContent = node.label;
      group.appendChild(label);
      var tooltip = svgEl("title", {});
      tooltip.textContent = (GRAPH_KIND_LABELS[node.kind] || node.kind) + " — " + node.title
        + (node.basis ? "\nbasis: " + node.basis : "");
      group.appendChild(tooltip);
      group.addEventListener("click", function () { onSelect(node); });
      nodeLayer.appendChild(group);
    });

    svg.appendChild(edgeLayer);
    svg.appendChild(nodeLayer);
    return svg;
  }

  function highlightPath(svg, path) {
    if (!svg) return;
    var nodes = {};
    var edges = {};
    (path.steps || []).forEach(function (step) {
      nodes[step.node] = true;
      if (step.edge) edges[step.node] = true;
    });
    var groups = svg.querySelectorAll(".graph-node");
    for (var i = 0; i < groups.length; i += 1) {
      var id = groups[i].getAttribute("data-id");
      groups[i].classList.toggle("dim", !nodes[id]);
    }
    var paths = svg.querySelectorAll(".graph-edge");
    for (var j = 0; j < paths.length; j += 1) {
      var source = paths[j].getAttribute("data-source");
      var target = paths[j].getAttribute("data-target");
      var on = nodes[source] && nodes[target];
      paths[j].classList.toggle("dim", !on);
      paths[j].classList.toggle("hot", !!on);
    }
  }

  function nodeDetail(node) {
    var host = el("div", {});
    var head = el("div", { class: "graph-detail-head" });
    head.appendChild(el("span", { class: "tag " + (node.severity === "critical" || node.severity === "high"
      ? "bad" : node.severity === "medium" ? "warn" : "info"), text: node.severity || "info" }));
    head.appendChild(el("b", { text: GRAPH_KIND_LABELS[node.kind] || node.kind }));
    head.appendChild(el("em", { text: node.basis || "observed" }));
    host.appendChild(head);
    host.appendChild(el("div", { class: "graph-detail-title", text: node.title || node.label }));
    if (node.detail) host.appendChild(el("div", { class: "hint", text: node.detail }));
    var list = el("div", { class: "kv" });
    Object.keys(node.meta || {}).forEach(function (key) {
      var value = node.meta[key];
      if (value === null || value === undefined || value === "" ) return;
      if (Array.isArray(value)) {
        if (!value.length) return;
        value = value.join(", ");
      }
      if (typeof value === "object") value = JSON.stringify(value);
      list.appendChild(el("dt", { text: key.replace(/_/g, " ") }));
      list.appendChild(el("dd", { text: String(value) }));
    });
    if (list.childNodes.length) host.appendChild(list);
    return host;
  }

  function viewGraph() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet("Nothing scanned yet",
        "The graph is drawn from what the scan found: the paths the target advertises, the " +
        "credentials and disclosures in the files it serves, the advisories its versions fall " +
        "into, and the routes from the front door to each of them."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);

    getJSON("/api/graph" + jobQuery()).then(function (graph) {
      var summary = graph.summary || {};
      var kpis = el("div", { class: "grid grid-kpi" });
      kpis.appendChild(kpi(num(summary.nodes), "nodes", "accent"));
      kpis.appendChild(kpi(num(summary.hosts), "hosts"));
      kpis.appendChild(kpi(num(summary.subdomains), "subdomains", summary.subdomains ? "warn" : ""));
      kpis.appendChild(kpi(num(summary.sub_subdomains), "sub-subdomains", summary.sub_subdomains ? "warn" : ""));
      kpis.appendChild(kpi(num(summary.paths), "attack paths", summary.paths ? "bad" : ""));
      kpis.appendChild(kpi(num(summary.credentials), "credentials", summary.credentials ? "bad" : ""));
      kpis.appendChild(kpi(num(summary.vulnerabilities), "demonstrated", summary.vulnerabilities ? "bad" : ""));
      kpis.appendChild(kpi(num(summary.cves), "advisories", summary.cves ? "warn" : ""));
      kpis.appendChild(kpi(num(summary.data_tables), "data tables"));
      kpis.appendChild(kpi(num(summary.sensitive_tables), "with personal columns",
        summary.sensitive_tables ? "warn" : ""));
      kpis.appendChild(kpi(num(summary.probes), "red-team probes"));
      host.appendChild(kpis);

      if (!graph.nodes || !graph.nodes.length) {
        host.appendChild(emptySection("The graph is empty",
          "The scan produced no nodes to draw. That is a bounded negative: the graph holds what " +
          "the tables of this scan hold, and no more."));
        return;
      }

      var layout = layoutGraph(graph);
      var detailHost = el("div", { class: "graph-detail" });
      var svg = drawGraphSVG(graph, layout, function (node) {
        detailHost.innerHTML = "";
        detailHost.appendChild(nodeDetail(node));
      });
      var graphCard = el("div", { class: "card graph-card" });
      var graphHead = el("h3");
      graphHead.appendChild(el("span", { text: "The graph" }));
      graphHead.appendChild(el("em", { text: graph.target || "" }));
      graphCard.appendChild(graphHead);
      graphCard.appendChild(el("div", { class: "hint", text:
        "The target is on the left. Each column is one hop further in. Click a node to read it; " +
        "click a path below to light up the route." }));
      var scroller = el("div", { class: "graph-canvas" });
      scroller.appendChild(svg);
      graphCard.appendChild(scroller);
      graphCard.appendChild(detailHost);
      host.appendChild(graphCard);

      var hostCard = el("div", { class: "card" });
      var hostHead = el("h3");
      hostHead.appendChild(el("span", { text: "Hosts" }));
      hostHead.appendChild(el("em", { text: (graph.hosts || []).length + " host(s)" }));
      hostCard.appendChild(hostHead);
      var hosts = graph.hosts || [];
      if (!hosts.length) {
        hostCard.appendChild(el("div", { class: "hint", text:
          "Only the target itself was found. The subdomain sweep is bounded, so a short list " +
          "here is a bounded negative, scoped to the prefixes that were tried." }));
      } else {
        hostCard.appendChild(el("div", { class: "hint", text:
          "The tree, from the registrable domain down. A host that resolves is a host the " +
          "target runs; a host that only a served file names is reported as it was written down." }));
        var tree = el("div", { class: "host-tree" });
        hosts.slice().sort(function (left, right) {
          if (left.depth !== right.depth) return left.depth - right.depth;
          return String(left.host).localeCompare(String(right.host));
        }).forEach(function (entry) {
          var row = el("div", { class: "host-row depth-" + Math.min(entry.depth || 0, 4) });
          row.appendChild(el("span", { class: "host-name", text: entry.host }));
          var note = el("span", { class: "host-note" });
          note.appendChild(el("span", {
            class: "tag " + (entry.source === "dns" ? "ok" : entry.source === "target" ? "info" : "warn"),
            text: entry.source || "seen"
          }));
          if (entry.parent) note.appendChild(el("span", { class: "hint", text: "under " + entry.parent }));
          if (entry.paths) note.appendChild(el("span", { class: "hint", text: entry.paths + " path(s)" }));
          row.appendChild(note);
          row.addEventListener("click", function () {
            var node = null;
            (graph.nodes || []).forEach(function (item) {
              if (item.kind === "host" && item.label === entry.host) node = item;
            });
            if (node) {
              detailHost.innerHTML = "";
              detailHost.appendChild(nodeDetail(node));
            }
          });
          tree.appendChild(row);
        });
        hostCard.appendChild(tree);
      }
      host.appendChild(hostCard);

      var paths = graph.paths || [];
      var pathCard = el("div", { class: "card" });
      var pathHead = el("h3");
      pathHead.appendChild(el("span", { text: "Attack paths" }));
      pathHead.appendChild(el("em", { text: paths.length + " route(s)" }));
      pathCard.appendChild(pathHead);
      if (!paths.length) {
        pathCard.appendChild(el("div", { class: "hint", text:
          "No route reaches a credential, a published record, an advisory, or a demonstrated " +
          "exposure. That is a bounded negative, scoped to the tables of this scan." }));
      } else {
        paths.forEach(function (path) {
          var row = el("div", { class: "graph-path" });
          var head = el("div", { class: "graph-path-head" });
          head.appendChild(el("span", {
            class: "tag " + (path.severity === "critical" || path.severity === "high" ? "bad"
              : path.severity === "medium" ? "warn" : "info"),
            text: path.severity || "info"
          }));
          head.appendChild(el("b", { text: path.summary }));
          head.appendChild(el("em", { text: "risk " + path.score }));
          row.appendChild(head);
          var trail = el("div", { class: "graph-trail" });
          (path.steps || []).forEach(function (step, index) {
            if (index) {
              trail.appendChild(el("span", { class: "graph-arrow", text: "→" }));
            }
            trail.appendChild(el("span", {
              class: "graph-step kind-" + step.kind,
              title: (step.edge_label || step.edge || "") + " · " + step.basis
            }, [el("span", { class: "graph-step-kind", text: GRAPH_KIND_LABELS[step.kind] || step.kind }),
                el("span", { class: "graph-step-label", text: step.label })]));
          });
          row.appendChild(trail);
          row.addEventListener("click", function () {
            highlightPath(svg, path);
            detailHost.innerHTML = "";
            detailHost.appendChild(el("div", { class: "graph-detail-title", text: path.summary }));
            detailHost.appendChild(el("div", { class: "hint", text:
              "A path is a route, not an exploit. Each hop is what the scan observed; the last " +
              "hop is what somebody would come for." }));
          });
          pathCard.appendChild(row);
        });
      }
      host.appendChild(pathCard);

      var dataCard = el("div", { class: "card" });
      var dataHead = el("h3");
      dataHead.appendChild(el("span", { text: "Exposed data" }));
      dataHead.appendChild(el("em", { text: (graph.data || []).length + " document(s)" }));
      dataCard.appendChild(dataHead);
      if (!(graph.data || []).length) {
        dataCard.appendChild(el("div", { class: "hint", text:
          "No data document was published. That is a bounded negative, scoped to the documents " +
          "the scan read." }));
      } else {
        dataCard.appendChild(tableElement(
          [
            { key: "table", label: "document", name: true, mono: true },
            { key: "rows", label: "rows", num: true },
            { key: "sensitive_columns", label: "personal columns", render: function (v) {
                return (v && v.length) ? '<span class="tag warn">' + escapeHtml(v.join(", ")) + "</span>" : "—";
              } },
            { key: "source", label: "source", mono: true },
            { key: "note", label: "note" }
          ],
          graph.data,
          { sortable: false }
        ));
      }
      host.appendChild(dataCard);
    }).catch(function (error) {
      host.innerHTML = "";
      host.appendChild(failureCard(error));
    });

    return fragment;
  }

  function viewCves() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet("Nothing scanned yet",
        "This page lists the advisories the observed versions fall into. The version is an " +
        "observation; the exposure is an inference, and it says what it needs besides."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    getJSON("/api/graph" + jobQuery()).then(function (graph) {
      host.innerHTML = "";
      var rows = graph.cves || [];
      if (!rows.length) {
        host.appendChild(emptySection("No advisory matched",
          "The catalogue was applied to the banner, the technology fingerprint, and the " +
          "dependency manifests this scan read. It is a small, offline catalogue, so a clean " +
          "result here is not a statement about the target."));
        return;
      }
      host.appendChild(summaryCard(
        rows.length + " advisory match(es).",
        "Each one is an inference from a version the target stated. The precondition travels " +
        "with it."
      ));
      host.appendChild(tableElement(
        [
          { key: "cve", label: "advisory", name: true, mono: true },
          { key: "component", label: "component" },
          { key: "severity", label: "severity", render: function (v) {
              var tone = v === "critical" || v === "high" ? "bad" : (v === "medium" ? "warn" : "info");
              return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
            } },
          { key: "cvss", label: "cvss", num: true },
          { key: "observed", label: "observed", mono: true },
          { key: "condition", label: "needs" },
          { key: "remediation", label: "fix" },
          { key: "confidence", label: "basis" }
        ],
        rows,
        { sortable: false }
      ));
    }).catch(function (error) {
      host.innerHTML = "";
      host.appendChild(failureCard(error));
    });
    return fragment;
  }

  // ------------------------------------------------------------ exploit agent

  var agentState = {
    running: false,
    events: [],
    result: null,
    job: "",
    error: ""
  };

  function viewAgent() {
    var fragment = document.createDocumentFragment();
    var host = el("div", {});
    fragment.appendChild(host);

    if (!hasScan()) {
      host.appendChild(noResultsYet("Nothing scanned yet",
        "The agent works from what the recon found: it reads the target's surface, asks a " +
        "model which checks are worth running, runs them against the target, and reports " +
        "what it proved. Run a recon first. The runs that already happened are listed below."));
    }

    var config = el("div", { class: "card" });
    var configHead = el("h3");
    configHead.appendChild(el("span", { text: "The agent" }));
    configHead.appendChild(el("em", { text: "a model plans the checks and writes the wording" }));
    config.appendChild(configHead);
    config.appendChild(el("div", { class: "hint", text:
      "The model runs on this machine by default: it never sees the target leave the box. It " +
      "reads a redacted picture of the target, chooses which of a fixed catalogue of checks " +
      "are worth running, and aims each one at a path the recon already saw. It cannot " +
      "invent a request, and it never sends one itself." }));

    var fields = el("div", { class: "grid grid-2", style: "margin-top:12px" });
    var endpointField = el("div", {});
    endpointField.appendChild(el("div", { class: "kpi-label", text: "model endpoint" }));
    var endpointInput = el("input", { class: "input", type: "text", value: "http://127.0.0.1:11434" });
    endpointField.appendChild(endpointInput);
    fields.appendChild(endpointField);
    var modelField = el("div", {});
    modelField.appendChild(el("div", { class: "kpi-label", text: "model" }));
    var modelInput = el("input", { class: "input", type: "text", value: "llama3.1" });
    modelField.appendChild(modelInput);
    fields.appendChild(modelField);
    config.appendChild(fields);

    var options = el("div", { class: "toolbar" });
    var apiSelect = el("select", { class: "input" });
    ["ollama", "openai"].forEach(function (name) {
      apiSelect.appendChild(el("option", { value: name, text: name }));
    });
    options.appendChild(apiSelect);
    var remoteLabel = el("label", { class: "check" });
    var remoteInput = el("input", { type: "checkbox" });
    remoteLabel.appendChild(remoteInput);
    remoteLabel.appendChild(el("span", { text: "allow a remote model (the target's shape leaves this machine)" }));
    options.appendChild(remoteLabel);
    config.appendChild(options);

    var ownedLabel = el("label", { class: "check", style: "margin-top:12px" });
    var ownedInput = el("input", { type: "checkbox" });
    ownedLabel.appendChild(ownedInput);
    ownedLabel.appendChild(el("span", { text: "I own this target, or I am authorised to probe it." }));
    config.appendChild(ownedLabel);

    var runButton = el("button", { class: "btn btn-primary", style: "margin-top:12px", text: "Run the agent" });
    runButton.disabled = true;
    ownedInput.addEventListener("change", function () {
      runButton.disabled = !ownedInput.checked || agentState.running || !hasScan();
    });
    config.appendChild(runButton);
    if (!hasScan()) {
      runButton.disabled = true;
      ownedInput.disabled = true;
      config.appendChild(el("div", { class: "hint", style: "margin-top:8px", text:
        "Select a scanned target first: the agent works from what the recon found." }));
    }
    host.appendChild(config);

    var progress = el("div", { class: "card log log-page", style: "margin-top:14px" });
    host.appendChild(progress);

    var verdict = (agentState.result || {}).verdict;
    if (verdict === "nothing-eligible") {
      var proved = el("div", { class: "banner warn", style: "margin-top:14px" });
      proved.appendChild(el("div", {
        text: "This run proved nothing: no request reached the target. The recon found no " +
          "model-backed endpoint and no guarded endpoint, and there was no observed path left " +
          "for a check to be aimed at. Zero findings here is a bounded negative, not evidence " +
          "that the target is safe."
      }));
      host.appendChild(proved);
    } else if (verdict === "assessed") {
      var assessment = (agentState.result || {}).assessment || {};
      host.appendChild(el("div", {
        class: "banner warn",
        style: "margin-top:14px",
        text: (assessment.checks_run || 0) + " check(s) ran and proved " +
          (assessment.checks_with_findings || 0) + " finding(s), but no forced-disclosure probe " +
          "was sent: the recon found no model-backed endpoint and no guarded endpoint. The " +
          "probe half of this run is a bounded negative."
      }));
    } else if (verdict === "probed" && agentState.result && !agentState.result.findings) {
      host.appendChild(el("div", {
        class: "banner",
        style: "margin-top:14px",
        text: (agentState.result.probes_sent || 0) + " probe(s) were sent and none of them leaked. " +
          "A refusal is a good outcome, and it is reported as one."
      }));
    }

    var resultHost = el("div", {});
    host.appendChild(resultHost);
    if (agentState.error) {
      host.appendChild(el("div", { class: "banner bad", style: "margin-top:14px", text: agentState.error }));
    }
    renderAssessment(resultHost);

    runButton.addEventListener("click", function () {
      agentState.running = true;
      agentState.events = [];
      runButton.disabled = true;
      progress.innerHTML = "";
      postJSON("/api/agent", {
        job: state.job || "",
        authorized: true,
        model_endpoint: endpointInput.value.trim(),
        model: modelInput.value.trim(),
        model_api: apiSelect.value,
        allow_remote_model: remoteInput.checked
      }).then(function (payload) {
        agentState.job = payload.id;
        listenAgent(payload.id);
      }).catch(function (error) {
        agentState.running = false;
        runButton.disabled = false;
        progress.appendChild(el("div", { class: "banner bad", text: String(error.message) }));
      });
    });

    getJSON("/api/agent").then(function (payload) {
      var jobs = payload.jobs || [];
      if (!jobs.length) return;
      var list = el("div", { class: "card", style: "margin-top:14px" });
      var head = el("h3");
      head.appendChild(el("span", { text: "Previous runs" }));
      list.appendChild(head);
      list.appendChild(tableElement(
        [
          { key: "id", label: "run", name: true, mono: true, render: function (v) {
              return '<a class="btn btn-ghost" href="#" data-agent-run="' + escapeAttr(v) + '">' +
                escapeHtml(v) + "</a>";
            } },
          { key: "url", label: "target", mono: true },
          { key: "status", label: "status" },
          { key: "checks", label: "checks", num: true },
          { key: "probes", label: "probes", num: true },
          { key: "findings", label: "findings", num: true },
          { key: "verdict", label: "verdict", render: function (v) {
              if (v === "nothing-eligible") {
                return '<span class="tag warn" title="no request reached the target; this run ' +
                  'proved nothing">nothing tested</span>';
              }
              if (v === "assessed") {
                return '<span class="tag warn" title="the checks ran, but no probe was sent">' +
                  "assessed</span>";
              }
              if (v === "probed") {
                return '<span class="tag ok">probed</span>';
              }
              return "—";
            } },
          { key: "report", label: "report", render: function (v, row) {
              if (!v) return "—";
              return '<a class="btn btn-ghost" href="/api/agent/' + encodeURIComponent(row.id) +
                '/report.pdf" download>PDF</a>';
            } }
        ],
        jobs,
        { sortable: false }
      ));
      list.querySelectorAll("[data-agent-run]").forEach(function (link) {
        link.addEventListener("click", function (event) {
          event.preventDefault();
          loadAgentRun(link.getAttribute("data-agent-run"));
        });
      });
      host.appendChild(list);
    }).catch(function () { /* the list is a nicety, not a requirement */ });

    return fragment;
  }

  /** Open a run that already happened, so its result can be read. */
  function loadAgentRun(runId) {
    getJSON("/api/agent/" + encodeURIComponent(runId)).then(function (payload) {
      agentState.job = runId;
      agentState.result = payload.result || {};
      agentState.error = "";
      setView("agent");
      render();
    }).catch(function () {
      agentState.error = "That run is no longer available.";
      setView("agent");
      render();
    });
  }

  /** The assessment: the checks that ran, what each one saw, and the model's reading. */
  function renderAssessment(host) {
    var assessment = (agentState.result || {}).assessment;
    if (!assessment || !assessment.checks || !assessment.checks.length) return;
    var card = el("div", { class: "card", style: "margin-top:14px" });
    var head = el("h3");
    head.appendChild(el("span", { text: "The assessment" }));
    head.appendChild(el("em", { text: "what was checked, and what each check saw" }));
    card.appendChild(head);
    card.appendChild(el("div", { class: "hint", text:
      "The model chose which of a fixed catalogue of checks to run, and aimed each one " +
      "at a path the recon had already observed. It could not invent a request, and it " +
      "never sent one itself: a check that finds something is the check's own evidence." }));

    var fromModel = assessment.model_plan || 0;
    var dropped = assessment.plan_dropped || 0;
    var meta = el("div", { class: "hint", style: "margin-top:10px" });
    meta.appendChild(el("span", { text:
      assessment.checks_planned + " check(s) planned, " + assessment.checks_run + " ran, " +
      (assessment.checks_with_findings || 0) + " proved a finding. " +
      fromModel + " came from the model" +
      (dropped ? ", and " + dropped + " proposal(s) were dropped as unusable." : ".") }));
    card.appendChild(meta);

    card.appendChild(tableElement(
      [
        { key: "check", label: "check", name: true, mono: true },
        { key: "target", label: "target", mono: true, render: function (v) {
            return v || "the host";
          } },
        { key: "source", label: "chosen by", render: function (v) {
            if (v === "model") return '<span class="tag info">the model</span>';
            return '<span class="tag">the catalogue</span>';
          } },
        { key: "outcome", label: "outcome", render: function (v) {
            var tone = v === "finding" ? "bad" : (v === "clear" ? "ok" : "warn");
            return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
          } },
        { key: "findings", label: "findings", num: true },
        { key: "why", label: "why", render: function (v) {
            if (!v) return "—";
            return '<span class="truncate" style="max-width:340px;display:inline-block" title="' +
              escapeAttr(v) + '">' + escapeHtml(v) + "</span>";
          } }
      ],
      assessment.checks,
      { sortable: false }
    ));

    if (assessment.summary) {
      card.appendChild(el("div", { class: "banner", style: "margin-top:12px", text: assessment.summary }));
    }

    if (assessment.narrative) {
      var note = el("div", { class: "banner", style: "margin-top:14px" });
      note.appendChild(el("div", { text: assessment.narrative }));
      note.appendChild(el("div", { class: "hint", style: "margin-top:8px", text:
        "This paragraph is the model's reading of what the checks observed. The findings " +
        "above are the checks' own, and the model did not change a severity." }));
      card.appendChild(note);
    } else if (assessment.narrative_dropped) {
      card.appendChild(el("div", { class: "banner warn", style: "margin-top:14px", text:
        "The model wrote a summary that claimed a weakness the checks did not prove, so the " +
        "summary was not included. The findings above are the checks' own, and they are the " +
        "whole of what this run proved." }));
    }
    host.appendChild(card);
  }

  function listenAgent(jobId) {
    var source = new EventSource("/api/agent/" + encodeURIComponent(jobId) + "/events");
    var progress = document.querySelector(".log.log-page");
    source.addEventListener("progress", function (message) {
      var event = JSON.parse(message.data);
      agentState.events.push(event);
      if (progress) progress.appendChild(logLine(event));
    });
    source.addEventListener("done", function (message) {
      var payload = JSON.parse(message.data);
      source.close();
      agentState.running = false;
      agentState.result = payload.result || {};
      if (payload.status === "error") {
        if (progress) progress.appendChild(el("div", { class: "banner bad", text: payload.error }));
        setPill("error", "failed");
        return;
      }
      setPill("ok", "complete");
      render();
    });
    source.onerror = function () {
      source.close();
      agentState.running = false;
      setPill("error", "offline");
    };
  }

  function viewProbes() {
    var fragment = document.createDocumentFragment();
    var host = el("div", {});
    fragment.appendChild(host);
    getJSON("/api/agent/table/agent-probes" + jobQuery()).then(function (payload) {
      host.innerHTML = "";
      var rows = payload.rows || [];
      if (!rows.length) {
        host.appendChild(emptySection("No probe was sent",
          "The agent has not run against this target. A probe that was never sent cannot " +
          "prove anything — run the agent, and this page fills in."));
        return;
      }
      var leaked = rows.filter(function (row) { return row.verdict === "leaked"; }).length;
      var refused = rows.filter(function (row) { return row.verdict === "refused"; }).length;
      host.appendChild(summaryCard(
        rows.length + " probe(s): " + leaked + " leaked, " + refused + " refused.",
        "A refusal is a good outcome, and it is reported as one."
      ));
      host.appendChild(tableElement(
        [
          { key: "verdict", label: "verdict", name: true, render: function (v) {
              var tone = v === "leaked" ? "bad" : (v === "refused" ? "ok" : "info");
              return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
            } },
          { key: "probe", label: "technique", mono: true },
          { key: "label", label: "probe" },
          { key: "endpoint", label: "endpoint", mono: true },
          { key: "source", label: "wording" },
          { key: "status", label: "status", num: true },
          { key: "markers", label: "markers", mono: true },
          { key: "evidence", label: "evidence", mono: true, render: function (v) {
              if (!v) return "—";
              return '<span class="truncate" style="max-width:420px;display:inline-block" title="' +
                escapeAttr(v) + '">' + escapeHtml(v) + "</span>";
            } }
        ],
        rows,
        { sortable: false }
      ));
    }).catch(function () {
      host.innerHTML = "";
      host.appendChild(emptySection("No probe table",
        "The agent has not produced a probe table for this target yet."));
    });
    return fragment;
  }

  function viewData() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page shows the documents the target publishes and the tables extracted from them."));
      return fragment;
    }
    var CATEGORY_ORDER = ["data", "page", "structure", "metadata"];
    var CATEGORY_LABELS = {
      data: "data document",
      page: "read from the page",
      structure: "structure and configuration",
      metadata: "metadata"
    };
    var dataTables = state.tables.filter(function (item) {
      return FIXED_TABLES.indexOf(item.name) < 0;
    }).sort(function (a, b) {
      var left = CATEGORY_ORDER.indexOf(a.category || "data");
      var right = CATEGORY_ORDER.indexOf(b.category || "data");
      if (left !== right) return left - right;
      return b.row_count - a.row_count;
    });
    if (!dataTables.length) {
      fragment.appendChild(emptySection("No data documents were extracted",
        "The scan found no JSON, GeoJSON, or CSV document to extract. The documents it did find " +
        "are listed under Paths & assets."));
      return fragment;
    }
    if (!state.dataTable || !dataTables.some(function (item) { return item.name === state.dataTable; })) {
      state.dataTable = dataTables[0].name;
    }
    var toolbar = el("div", { class: "toolbar" });
    var select = el("select", { class: "input" });
    dataTables.forEach(function (item) {
      var category = CATEGORY_LABELS[item.category] || item.category || "data";
      var origin = item.source ? " · " + item.source : "";
      select.appendChild(el("option", {
        value: item.name,
        text: item.name + origin + " — " + category + " (" + num(item.row_count) + ")"
      }));
    });
    select.value = state.dataTable;
    select.addEventListener("change", function () {
      state.dataTable = select.value;
      render();
    });
    toolbar.appendChild(select);
    var count = el("span", { class: "hint" });
    toolbar.appendChild(count);
    fragment.appendChild(toolbar);

    var host = el("div", {});
    fragment.appendChild(host);

    var active = tableMeta(state.dataTable);
    loadTable(state.dataTable).then(function (info) {
      var rows = state.rows[state.dataTable] || [];
      var columns = info.columns.length ? info.columns : (rows[0] ? Object.keys(rows[0]) : []);
      count.textContent = num(info.rowCount) + " row(s)"
        + (rows.length < info.rowCount ? " — showing the first " + rows.length : "");
      host.innerHTML = "";
      host.appendChild(summaryCard(
        state.dataTable + " — " + num(info.rowCount) + " row(s), " + columns.length + " column(s).",
        ((active && active.note) || "extracted from a document the target publishes")
        + " · " + (CATEGORY_LABELS[(active && active.category) || "data"] || "data")
      ));
      if (!rows.length) {
        host.appendChild(emptySection("This table is empty", "The document was read, and held no records."));
        return;
      }
      host.appendChild(tableElement(
        columns.slice(0, 16).map(function (key) {
          return { key: key, label: key, mono: /url|path|hash|sha/i.test(key) };
        }),
        rows
      ));
    });
    return fragment;
  }

  function viewTriage() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page reads the target's own response headers as a statement about its posture."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("triage").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.triage || [];
      if (!rows.length) {
        host.appendChild(emptySection("No triage was recorded", "The target did not answer with headers to read."));
        return;
      }
      var verdicts = countBy(rows, "status");
      host.appendChild(summaryCard(
        (verdicts.fail || 0) + " failing, " + (verdicts.warn || 0) + " warning(s), " +
        (verdicts.pass || 0) + " passing.",
        "The target's own headers, read as a statement about its posture."
      ));
      host.appendChild(tableElement(
        [
          { key: "check", label: "check", name: true },
          { key: "status", label: "verdict", render: function (v) {
              var tone = v === "fail" ? "bad" : (v === "warn" ? "warn" : (v === "pass" ? "ok" : "info"));
              return '<span class="tag ' + tone + '">' + escapeHtml(v || "—") + "</span>";
            } },
          { key: "severity", label: "severity" },
          { key: "detail", label: "detail" }
        ],
        rows,
        { sortable: false }
      ));
    });
    return fragment;
  }

  function viewCoverage() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page states what the scan looked at, and what it did not. A scan that reports what " +
        "it found without reporting what it skipped is not a measurement."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("coverage").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.coverage || [];
      host.appendChild(summaryCard(
        "What the scan looked at, and what it did not.",
        "Absence of a finding is not proof of absence."
      ));
      if (!rows.length) {
        host.appendChild(emptySection("No coverage was recorded", "The run did not report its coverage."));
        return;
      }
      host.appendChild(tableElement(
        [
          { key: "area", label: "area", name: true },
          { key: "checked", label: "checked", num: true },
          { key: "total", label: "total", num: true },
          { key: "status", label: "status" },
          { key: "note", label: "note" }
        ],
        rows,
        { sortable: false }
      ));
    });
    return fragment;
  }

  function viewAudit() {
    var fragment = document.createDocumentFragment();
    if (!hasScan()) {
      fragment.appendChild(noResultsYet(
        expiredScan() ? "That run is no longer available" : "Nothing scanned yet",
        expiredScan()
          ? "The console was restarted, and the run it referred to is gone. Run the scan again."
          : "This page lists every request the run made, including the ones that were refused or " +
        "answered 304."));
      return fragment;
    }
    var host = el("div", {});
    fragment.appendChild(host);
    loadTable("audit").then(function (info) {
      host.innerHTML = "";
      if (!info.available) {
        host.appendChild(emptySection("This table is not in the current scan",
          "This section belongs to a recon run. Run a recon against the target to fill it in."));
        return;
      }
      var rows = state.rows.audit || [];
      host.appendChild(summaryCard(
        rows.length + " request(s) recorded.",
        "Every request the run made, with its outcome, status, size, and duration."
      ));
      if (!rows.length) {
        host.appendChild(emptySection("No request was recorded", "The audit log is empty."));
        return;
      }
      host.appendChild(tableElement(
        [
          { key: "timestamp", label: "time", mono: true },
          { key: "method", label: "method" },
          { key: "url", label: "url", mono: true },
          { key: "outcome", label: "outcome" },
          { key: "status", label: "status", num: true },
          { key: "bytes", label: "bytes", num: true },
          { key: "duration_ms", label: "ms", num: true },
          { key: "note", label: "note" }
        ],
        rows
      ));
    });
    return fragment;
  }

  function viewLog() {
    var fragment = document.createDocumentFragment();
    var events = state.jobEvents || [];
    if (!events.length) {
      fragment.appendChild(noResultsYet("No run log yet",
        "The run log is written as the scan proceeds. Run a recon and this page fills in step by " +
        "step."));
      return fragment;
    }
    var host = el("div", { class: "log log-page" });
    fragment.appendChild(host);
    events.forEach(function (event) { host.appendChild(logLine(event)); });
    return fragment;
  }

  function logLine(event) {
    var line = el("div", { class: "log-line level-" + (event.level || "info") });
    line.appendChild(el("span", { class: "log-time", text: clockOf(event.at).slice(11) }));
    line.appendChild(el("span", { class: "log-pct", text: String(event.percent).padStart(3, " ") + "%" }));
    line.appendChild(el("span", { class: "log-phase", text: event.phase || "" }));
    line.appendChild(el("span", { class: "log-msg", text: event.message || "" }));
    if (event.detail) line.appendChild(el("span", { class: "log-detail", text: event.detail }));
    return line;
  }

  // ----------------------------------------------------------------- modal

  var modal = {
    open: function (url) {
      document.getElementById("modal").hidden = false;
      document.getElementById("modal").classList.add("open");
      document.getElementById("preflight").hidden = false;
      document.getElementById("progress").hidden = true;
      document.getElementById("result").hidden = true;
      document.getElementById("btn-start").hidden = false;
      document.getElementById("btn-view-results").hidden = true;
      document.getElementById("modal-cancel").hidden = false;
      document.getElementById("modal-close").hidden = false;
      document.getElementById("chk-owned").checked = false;
      document.getElementById("chk-active").checked = false;
      document.getElementById("preflight-error").hidden = true;
      document.getElementById("log").innerHTML = "";
      document.getElementById("modal-sub").textContent = url;
      document.getElementById("modal-title").textContent = "Recon — preflight";
      document.getElementById("btn-start").disabled = true;
    },
    close: function () {
      document.getElementById("modal").classList.remove("open");
      setTimeout(function () { document.getElementById("modal").hidden = true; }, 160);
    }
  };

  function setProgress(event) {
    document.getElementById("progress-fill").style.width = event.percent + "%";
    document.getElementById("progress-percent").textContent = event.percent + "%";
    document.getElementById("phase-label").textContent = event.phase || "";
    var log = document.getElementById("log");
    log.appendChild(logLine(event));
    log.scrollTop = log.scrollHeight;
  }

  function startScan() {
    var url = document.getElementById("scan-url").value.trim();
    if (!url) return;
    document.getElementById("preflight").hidden = true;
    document.getElementById("progress").hidden = false;
    document.getElementById("btn-start").hidden = true;
    document.getElementById("modal-title").textContent = "Recon — running";
    setPill("busy", "scanning");
    state.jobEvents = [];
    state.rows = {};
    state.tableInfo = {};

    var active = document.getElementById("chk-active").checked;
    var userAgent = (document.getElementById("scan-ua").value || "").trim();
    postJSON("/api/recon", {
      url: url,
      authorized: true,
      active: active,
      user_agent: userAgent
    }).then(function (payload) {
      state.job = payload.id;
      document.getElementById("modal-sub").textContent = payload.url;
      listen(payload.id);
    }).catch(function (error) {
      document.getElementById("preflight").hidden = false;
      document.getElementById("progress").hidden = true;
      document.getElementById("btn-start").hidden = false;
      var box = document.getElementById("preflight-error");
      box.textContent = error.message;
      box.hidden = false;
      setPill("error", "error");
    });
  }

  function listen(jobId) {
    var source = new EventSource("/api/recon/" + encodeURIComponent(jobId) + "/events");
    source.addEventListener("progress", function (message) {
      var event = JSON.parse(message.data);
      state.jobEvents.push(event);
      setProgress(event);
    });
    source.addEventListener("done", function (message) {
      var payload = JSON.parse(message.data);
      source.close();
      state.jobResult = payload.result || {};
      if (payload.status === "error") {
        setPill("error", "failed");
        document.getElementById("modal-title").textContent = "Recon — failed";
        var box = document.getElementById("preflight-error");
        box.textContent = payload.error || "the run failed";
        box.hidden = false;
        document.getElementById("preflight").hidden = false;
        document.getElementById("progress").hidden = true;
        return;
      }
      if (payload.status === "refused") {
        // A refusal is the target's answer, not a failure of the tool.
        setPill("error", "refused");
        document.getElementById("modal-title").textContent = "Recon — refused";
        state.jobResult = payload.result || {};
        showResult(payload.result || {});
        loadJobDataset(state.job);
        return;
      }
      setPill("ok", "complete");
      document.getElementById("modal-title").textContent = "Recon — complete";
      showResult(payload.result || {});
      loadJobDataset(jobId);
    });
    source.onerror = function () {
      source.close();
      setPill("error", "offline");
    };
  }

  function showResult(result) {
    document.getElementById("progress").hidden = true;
    document.getElementById("result").hidden = false;
    document.getElementById("btn-view-results").hidden = false;
    document.getElementById("modal-cancel").hidden = true;

    var grid = document.getElementById("result-grid");
    grid.innerHTML = "";
    [
      [num(result.endpoints), "paths & assets", "accent"],
      [num(result.exposed), "exposed", result.exposed ? "bad" : ""],
      [num(result.leaks), "credentials", result.leaks ? "bad" : ""],
      [num(result.information), "disclosures", result.information ? "warn" : ""],
      [num(result.recovered), "files recovered", result.recovered ? "warn" : ""],
      [num(result.vulnerabilities), "proven exposures", result.vulnerabilities ? "bad" : ""],
      [num(result.spec_endpoints), "API endpoints", ""],
      [num(result.total_rows), "rows extracted", "accent"],
      [num(result.requests), "requests", ""],
      [seconds(result.duration_seconds), "duration", ""]
    ].forEach(function (item) {
      var cell = el("div", { class: "result-cell" });
      cell.appendChild(el("div", { class: "kpi-value" + (item[2] ? " kpi-" + item[2] : ""), text: item[0] }));
      cell.appendChild(el("div", { class: "kpi-label", text: item[1] }));
      grid.appendChild(cell);
    });

    var notes = document.getElementById("result-notes");
    notes.innerHTML = "";
    if (result.leak_kinds && result.leak_kinds.length) {
      notes.appendChild(el("div", { class: "banner bad", text: "Credential-shaped strings found: " + result.leak_kinds.join(", ") }));
    }
    (result.warnings || []).forEach(function (warning) {
      notes.appendChild(el("div", { class: "banner", text: warning }));
    });
    (result.warnings || []).forEach(function (warning) {
      notes.appendChild(el("div", { class: "banner", text: warning }));
    });
    notes.appendChild(el("div", { class: "hint", text:
      "The scan covered the paths listed in the surface table and nothing else. The credential " +
      "patterns were applied to the documents that were read; that is a bounded negative, " +
      "not a proof that the target holds no secrets." }));
  }

  function loadJobDataset(jobId) {
    Promise.all([
      getJSON("/api/stats" + jobQuery()),
      getJSON("/api/tables" + jobQuery())
    ]).then(function (payload) {
      state.stats = payload[0].stats || {};
      state.meta = payload[0].meta || {};
      state.tables = payload[1].tables || [];
      state.recon = state.meta.recon || {};
      document.getElementById("foot-target").textContent = state.recon.target || state.meta.target || "—";
      document.getElementById("foot-tables").textContent = state.tables.length;
      document.getElementById("foot-generated").textContent = state.meta.generated_at || "—";
      if (state.recon.target) document.getElementById("scan-url").value = state.recon.target;
      setPill("ok", "complete");
      var jsonLink = document.getElementById("btn-json");
      var pdfLink = document.getElementById("btn-pdf");
      jsonLink.href = "/api/recon/" + encodeURIComponent(jobId) + "/dataset.json";
      pdfLink.href = "/api/recon/" + encodeURIComponent(jobId) + "/report.pdf";
      render();
      loadTargets();
    }).catch(function () {
      setPill("error", "offline");
    });
  }

  // --------------------------------------------------------------- job load

  function rememberJob(jobId) {
    try {
      window.localStorage.setItem("red-alert.job", jobId);
    } catch (error) {
      /* a private window may refuse storage; the console still works */
    }
  }

  function lastJob() {
    try {
      return window.localStorage.getItem("red-alert.job") || "";
    } catch (error) {
      return "";
    }
  }

  function attachJob(jobId, openModal) {
    state.job = jobId;
    rememberJob(jobId);
    state.rows = {};
    state.tableInfo = {};
    getJSON("/api/recon/" + encodeURIComponent(jobId)).then(function (snapshot) {
      state.jobAvailable = true;
      state.jobEvents = snapshot.events || [];
      state.jobResult = snapshot.result || {};
      if (snapshot.status === "running" || snapshot.status === "pending") {
        openRunningModal(jobId);
        return;
      }
      if (snapshot.status === "error") {
        setPill("error", "failed");
        return;
      }
      setPill("ok", "complete");
      loadJobDataset(jobId);
    }).catch(function () {
      state.jobAvailable = false;
      state.job = null;
      setPill("error", "expired");
      var notes = document.getElementById("scan-url");
      if (notes) notes.setAttribute("placeholder", "https://target.example — press Enter to recon");
      render();
      renderTargets();
    });
  }

  function openRunningModal(jobId) {
    document.getElementById("modal").hidden = false;
    document.getElementById("modal").classList.add("open");
    document.getElementById("preflight").hidden = true;
    document.getElementById("progress").hidden = false;
    document.getElementById("result").hidden = true;
    document.getElementById("btn-start").hidden = true;
    document.getElementById("btn-view-results").hidden = true;
    document.getElementById("modal-cancel").hidden = true;
    document.getElementById("modal-close").hidden = false;
    document.getElementById("modal-title").textContent = "Recon — running";
    document.getElementById("modal-sub").textContent = jobId;
    document.getElementById("log").innerHTML = "";
    state.jobEvents.forEach(function (event) { setProgress(event); });
    setPill("busy", "scanning");
    listen(jobId);
  }

  // ------------------------------------------------------------------ boot

  // A view that throws must say so. An empty page is indistinguishable from
  // an empty result, and that distinction matters here.
  window.addEventListener("error", function (event) {
    showFailure(event.error || event.message);
  });
  window.addEventListener("unhandledrejection", function (event) {
    showFailure(event.reason);
  });

  function showFailure(error) {
    var content = document.getElementById("content");
    if (!content) return;
    content.innerHTML = "";
    content.appendChild(failureCard(error));
  }

  document.addEventListener("DOMContentLoaded", function () {
    var nav = document.getElementById("nav");
    if (nav) {
      nav.addEventListener("click", function (event) {
        var button = event.target.closest ? event.target.closest(".nav-item") : null;
        if (!button) return;
        setView(button.getAttribute("data-view"));
      });
    }
    window.addEventListener("hashchange", function () {
      var requested = window.location.hash.slice(1);
      if (VIEWS[requested] && requested !== state.view) setView(requested);
    });

    var input = document.getElementById("scan-url");
    input.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        modal.open(input.value.trim());
      }
    });
    document.getElementById("btn-scan").addEventListener("click", function () {
      modal.open(input.value.trim());
    });
    document.getElementById("chk-owned").addEventListener("change", function (event) {
      document.getElementById("btn-start").disabled = !event.target.checked;
    });
    document.getElementById("btn-start").addEventListener("click", startScan);
    document.getElementById("modal-close").addEventListener("click", modal.close);
    document.getElementById("modal-cancel").addEventListener("click", modal.close);
    document.getElementById("btn-view-results").addEventListener("click", function () {
      modal.close();
      setView("overview");
    });
    document.getElementById("modal").addEventListener("click", function (event) {
      if (event.target === document.getElementById("modal")) modal.close();
    });

    var requested = window.location.hash.slice(1);
    if (VIEWS[requested]) {
      state.view = requested;
      applyViewMeta(requested);
    }
    render();
    loadTargets();

    var params = new URLSearchParams(window.location.search);
    var jobId = params.get("job");
    var target = params.get("url");

    if (target) {
      input.value = target;
      modal.open(target);
    }

    if (jobId) {
      attachJob(jobId, true);
      return;
    }

    // A reload should not lose the run: the last job is remembered, and the
    // page opens on its results.
    var previous = lastJob();
    if (previous) {
      attachJob(previous, false);
      return;
    }

    getJSON("/api/status").then(function (status) {
      state.meta = status.dataset_meta || {};
      state.recon = state.meta.recon || {};
      setPill("idle", "ready");
      if (status.has_dataset) {
        Promise.all([getJSON("/api/tables"), getJSON("/api/stats")]).then(function (payload) {
          state.tables = payload[0].tables || [];
          state.stats = payload[1].stats || {};
          document.getElementById("foot-tables").textContent = state.tables.length;
          document.getElementById("foot-generated").textContent = state.meta.generated_at || "—";
          render();
        }).catch(function () { render(); });
        return;
      }
      render();
    }).catch(function () {
      setPill("error", "offline");
      render();
    });
  });
})();
