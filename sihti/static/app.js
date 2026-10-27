"use strict";
// Sihti – käyttöliittymä. Kaikki palvelimelta tuleva teksti asetetaan textContentilla.

const $ = (s) => document.querySelector(s);
const fmt = new Intl.NumberFormat("fi-FI");
const STATUS_LABEL = { estetty: "Estetty", sallittu: "Sallittu", valimuisti: "Välimuisti", virhe: "Virhe" };
const REASON_LABEL = { lista: "estolista", oma: "oma esto", lauseke: "lauseke", "ylävirta": "ylävirta ei vastannut" };

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "X-Sihti": "1" } };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const r = await fetch(path, init);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "/api/login") { showLogin(); throw new Error("kirjaudu"); }
  if (!r.ok) throw new Error(data.error || `virhe ${r.status}`);
  return data;
}

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "text") e.textContent = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}

function flash(node, text) {
  node.textContent = text;
  clearTimeout(node._t);
  node._t = setTimeout(() => (node.textContent = ""), 4000);
}

const timeFmt = (ts) => new Date(ts * 1000).toLocaleTimeString("fi-FI", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dateFmt = (ts) => ts ? new Date(ts * 1000).toLocaleString("fi-FI", { day: "numeric", month: "numeric", hour: "2-digit", minute: "2-digit" }) : "ei koskaan";

/* ---------- kirjautuminen ---------- */
function showLogin() { $("#app").hidden = true; $("#login").hidden = false; $("#pw").focus(); }
async function boot() {
  const s = await fetch("/api/session").then((r) => r.json());
  if (s.auth_required && !s.logged_in) return showLogin();
  $("#logout").hidden = !s.auth_required;
  $("#login").hidden = true;
  $("#app").hidden = false;
  route();
  refreshStatus();
  setInterval(refreshStatus, 10000);
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/login", { method: "POST", body: { password: $("#pw").value } });
    $("#pw").value = "";
    boot();
  } catch (err) { $("#login-error").textContent = err.message; }
});
$("#logout").addEventListener("click", async () => { await api("/api/logout", { method: "POST" }); location.reload(); });

/* ---------- navigointi ---------- */
const views = ["yleiskuva", "loki", "saannot", "listat", "asetukset"];
let current = null;
function route() {
  const name = views.includes(location.hash.slice(1)) ? location.hash.slice(1) : "yleiskuva";
  current = name;
  for (const v of views) $(`#v-${v}`).hidden = v !== name;
  document.querySelectorAll(".tabs a").forEach((a) => {
    if (a.getAttribute("href") === `#${name}`) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  ({ yleiskuva: loadOverview, loki: loadLog, saannot: loadRules, listat: loadLists, asetukset: loadSettings })[name]();
}
window.addEventListener("hashchange", route);

/* ---------- tila ja suodatuskytkin ---------- */
let status = null;
async function refreshStatus() {
  try { status = await api("/api/status"); } catch { return; }
  const dot = $("#state-dot"), txt = $("#state-text"), btn = $("#toggle");
  dot.className = "dot " + (status.blocking ? "on" : "off");
  if (status.blocking) txt.textContent = "Suodatus päällä";
  else if (status.blocking_enabled && status.pause_until) txt.textContent = "Tauolla klo " + new Date(status.pause_until * 1000).toLocaleTimeString("fi-FI", { hour: "2-digit", minute: "2-digit" }) + " asti";
  else txt.textContent = "Suodatus pois";
  btn.textContent = status.blocking ? "Poista käytöstä" : "Ota käyttöön";
  $("#pause").hidden = !status.blocking;
  if (current === "yleiskuva") renderHeadline();
}
$("#toggle").addEventListener("click", async () => {
  await api("/api/blocking", { method: "POST", body: { enabled: !status.blocking } });
  refreshStatus();
});
$("#pause").addEventListener("change", async (e) => {
  if (!e.target.value) return;
  await api("/api/blocking", { method: "POST", body: { pause_seconds: Number(e.target.value) } });
  e.target.value = "";
  refreshStatus();
});

/* ---------- yleiskuva ---------- */
function renderHeadline() {
  if (!status) return;
  const p = $("#headline");
  p.replaceChildren();
  if (!status.total) { p.textContent = "Ei vielä kyselyjä. Aseta tämän laitteen osoite reitittimesi DNS-palvelimeksi."; return; }
  const pct = Math.round((status.blocked / status.total) * 1000) / 10;
  p.append("Viimeisen vuorokauden aikana ", el("b", { text: fmt.format(status.total) }), " kyselyä, joista ",
    el("b", { class: "caught", text: `${fmt.format(status.blocked)} (${String(pct).replace(".", ",")} %)` }), " jäi sihtiin.");
  const facts = [
    [fmt.format(status.domains_on_lists), "nimeä estolistoilla"],
    [fmt.format(status.clients), "laitetta käytti palvelua"],
    [fmt.format(status.cached), "vastausta välimuistista"],
    [dateFmt(status.last_update), "listat päivitetty"],
  ];
  $("#facts").replaceChildren(...facts.map(([v, k]) => el("div", {}, el("dt", { text: k }), el("dd", { text: v }))));
}

async function loadOverview() {
  renderHeadline();
  const [tl, top] = await Promise.all([api("/api/timeline?hours=24"), api("/api/top?hours=24")]);
  drawChart(tl);
  for (const [id, rows] of [["top-blocked", top.blocked], ["top-domains", top.domains], ["top-clients", top.clients]]) {
    const ol = $("#" + id);
    if (!rows.length) { ol.replaceChildren(el("li", { class: "empty", text: "Ei vielä tietoja." })); continue; }
    const max = rows[0].count;
    ol.replaceChildren(...rows.map((r) => {
      const bar = el("span", { class: "bar" });
      bar.style.width = (r.count / max) * 100 + "%";
      return el("li", { title: r.name }, bar, el("span", { class: "name", text: r.name }), el("span", { class: "n", text: fmt.format(r.count) }));
    }));
  }
}

// "Sihtikaavio": läpäisseet kyselyt pylväinä viivan yläpuolella, estetyt roikkuvat viivan alla.
function drawChart(data) {
  const svg = $("#chart");
  const W = svg.clientWidth || 800, H = svg.clientHeight || 260;
  const NS = "http://www.w3.org/2000/svg";
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.replaceChildren();
  const maxOk = Math.max(1, ...data.map((d) => d.allowed));
  const maxNo = Math.max(1, ...data.map((d) => d.blocked));
  const total = maxOk + maxNo;
  const mesh = Math.round(H * Math.min(0.72, Math.max(0.45, maxOk / total)));
  const top = 6, bottom = H - 2;
  const n = data.length, step = W / n, bw = Math.max(1, step - (step > 4 ? 1.5 : 0.5));
  const scaleUp = (mesh - top) / maxOk, scaleDown = (bottom - mesh - 4) / Math.max(maxNo, maxOk * 0.25);
  const mk = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };

  data.forEach((d, i) => {
    const x = i * step;
    const label = `${new Date(d.t * 1000).toLocaleTimeString("fi-FI", { hour: "2-digit", minute: "2-digit" })}: ${d.allowed} läpäisi, ${d.blocked} estettiin`;
    if (d.allowed) {
      const h = d.allowed * scaleUp;
      const r = mk("rect", { x, y: mesh - h, width: bw, height: h, class: "ok", rx: 1 });
      r.append(mk("title", {})); r.lastChild.textContent = label;
      svg.append(r);
    }
    if (d.blocked) {
      const h = Math.max(2, d.blocked * scaleDown);
      const r = mk("rect", { x, y: mesh + 3, width: bw, height: h, class: "no", rx: 1 });
      r.append(mk("title", {})); r.lastChild.textContent = label;
      svg.append(r);
    }
  });
  svg.append(mk("line", { x1: 0, x2: W, y1: mesh + 1.5, y2: mesh + 1.5, class: "mesh" }));

  const ax = $("#axis");
  const ticks = 5;
  ax.replaceChildren(...Array.from({ length: ticks }, (_, i) => {
    const d = data[Math.min(n - 1, Math.round((i / (ticks - 1)) * (n - 1)))];
    return el("span", { text: d ? new Date(d.t * 1000).toLocaleTimeString("fi-FI", { hour: "2-digit", minute: "2-digit" }) : "" });
  }));
}
window.addEventListener("resize", () => { if (current === "yleiskuva") loadOverview(); });

/* ---------- kyselyloki ---------- */
let logTimer = null;
async function loadLog() {
  clearInterval(logTimer);
  await renderLog();
  logTimer = setInterval(() => { if (current === "loki" && $("#log-live").checked) renderLog(); }, 3000);
}
async function renderLog() {
  const q = new URLSearchParams({ limit: 300 });
  if ($("#log-search").value) q.set("search", $("#log-search").value);
  if ($("#log-status").value) q.set("status", $("#log-status").value);
  const rows = await api("/api/log?" + q);
  const body = $("#log-body");
  if (!rows.length) { body.replaceChildren(el("tr", {}, el("td", { colspan: 7, class: "empty", text: "Ei kyselyjä näillä ehdoilla." }))); return; }
  body.replaceChildren(...rows.map((r) => {
    const tag = el("span", { class: "tag " + r.status, text: STATUS_LABEL[r.status] || r.status });
    if (r.reason) tag.title = REASON_LABEL[r.reason] || r.reason;
    const action = r.status === "estetty"
      ? el("button", { class: "linkbtn", text: "Salli", onclick: () => quickRule("allow", r.domain) })
      : el("button", { class: "linkbtn", text: "Estä", onclick: () => quickRule("deny", r.domain) });
    return el("tr", { class: r.status },
      el("td", { text: timeFmt(r.ts) }), el("td", { text: r.client }), el("td", { class: "dom", text: r.domain }),
      el("td", { text: r.qtype }), el("td", {}, tag), el("td", { class: "r", text: r.ms ?? "" }), el("td", {}, action));
  }));
}
async function quickRule(kind, domain) {
  const verb = kind === "allow" ? "Sallitaanko" : "Estetäänkö";
  if (!confirm(`${verb} ${domain} ja sen aliverkkotunnukset?`)) return;
  try { await api("/api/custom", { method: "POST", body: { kind, value: domain } }); renderLog(); }
  catch (e) { alert(e.message); }
}
let searchT;
$("#log-search").addEventListener("input", () => { clearTimeout(searchT); searchT = setTimeout(renderLog, 300); });
$("#log-status").addEventListener("change", renderLog);

/* ---------- omat säännöt ---------- */
async function loadRules() {
  const d = await api("/api/custom");
  for (const kind of ["allow", "deny", "deny_regex"]) {
    const ul = $("#list-" + kind);
    if (!d[kind].length) { ul.replaceChildren(el("li", { class: "empty", text: "Ei sääntöjä." })); continue; }
    ul.replaceChildren(...d[kind].map((v) => el("li", {}, el("span", { text: v }),
      el("button", { class: "linkbtn", text: "Poista", "aria-label": `Poista ${v}`, onclick: async () => {
        await api("/api/custom", { method: "DELETE", body: { kind, value: v } }); loadRules();
      } }))));
  }
}
document.querySelectorAll("form.add").forEach((f) => {
  const input = f.querySelector("textarea");
  const msg = f.querySelector(".msg");
  // Ctrl/Cmd+Enter tallentaa, pelkkä Enter tekee uuden rivin
  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) f.requestSubmit(); });
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await api("/api/custom", { method: "POST", body: { kind: f.dataset.kind, value: input.value } });
      const parts = [`${r.added.length} lisätty`];
      if (r.existing.length) parts.push(`${r.existing.length} oli jo listalla`);
      if (r.invalid.length) parts.push(`ohitettiin: ${r.invalid.slice(0, 3).join(", ")}${r.invalid.length > 3 ? "…" : ""}`);
      flash(msg, parts.join(", ") + ".");
      input.value = r.invalid.join("\n");  // virheelliset jäävät kenttään korjattaviksi
      loadRules();
    } catch (err) { flash(msg, err.message); }
  });
});
$("#check-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#check-result");
  let r;
  try { r = await api("/api/check?domain=" + encodeURIComponent($("#check-domain").value)); }
  catch (err) { out.className = "no"; out.textContent = err.message; return; }
  out.className = r.blocked ? "no" : "ok";
  out.textContent = r.blocked ? `${r.domain} estetään (${REASON_LABEL[r.reason] || r.reason}).` : `${r.domain} päästetään läpi.`;
});

/* ---------- estolistat ---------- */
async function loadLists(data) {
  const lists = data || await api("/api/lists");
  const total = lists.filter((l) => l.enabled).reduce((s, l) => s + (l.count || 0), 0);
  $("#list-summary").textContent = `${lists.length} listaa, käytössä olevissa yhteensä ${fmt.format(total)} riviä (päällekkäiset lasketaan kerran suodatuksessa).`;
  $("#lists").replaceChildren(...lists.map((l) => {
    const cb = el("input", { type: "checkbox", "aria-label": "Käytössä" });
    cb.checked = l.enabled;
    cb.addEventListener("change", async () => loadLists(await api("/api/lists", { method: "PATCH", body: { url: l.url, enabled: cb.checked } })));
    const meta = el("div", { class: "meta" }, `${fmt.format(l.count || 0)} nimeä · päivitetty ${dateFmt(l.updated)}`);
    if (l.error) meta.append(" · ", el("span", { class: "err", text: "viimeisin lataus epäonnistui: " + l.error }));
    return el("li", { class: l.enabled ? "" : "off" }, cb, el("div", { class: "url", text: l.url }),
      el("button", { class: "linkbtn", text: "Poista", onclick: async () => {
        if (confirm("Poistetaanko lista?")) loadLists(await api("/api/lists", { method: "DELETE", body: { url: l.url } }));
      } }), meta);
  }));
}
$("#list-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { loadLists(await api("/api/lists", { method: "POST", body: { url: $("#list-url").value } })); $("#list-url").value = ""; }
  catch (err) { alert(err.message); }
});
$("#list-update").addEventListener("click", async (e) => {
  const b = e.target;
  b.disabled = true; b.textContent = "Päivitetään…";
  await api("/api/lists/update", { method: "POST" });
  const before = status?.last_update;
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    await refreshStatus();
    if (status?.last_update !== before) break;
  }
  b.disabled = false; b.textContent = "Päivitä listat nyt";
  loadLists();
});

/* ---------- asetukset ---------- */
async function loadSettings() {
  const s = await api("/api/settings");
  $("#s-upstreams").value = s.upstreams.join("\n");
  document.querySelectorAll("input[name=block_mode]").forEach((r) => (r.checked = r.value === s.block_mode));
  $("#s-retention").value = s.log_retention_days;
  $("#s-cache").value = s.cache_size;
  $("#s-interval").value = s.update_interval_hours;
  $("#s-log").checked = s.log_queries;
  loadTls();
  $("#pw-state").textContent = s.has_password ? "Salasana on asetettu." : "Salasanaa ei ole asetettu – kuka tahansa lähiverkossa voi muuttaa asetuksia.";
}
async function loadTls() {
  const t = await api("/api/tls");
  const state = $("#tls-state"), info = $("#tls-info");
  $("#tls-ca").hidden = !(t.enabled && t.ca_fingerprint);
  $("#tls-renew").hidden = !(t.enabled && !t.custom);
  if (!t.enabled) {
    state.textContent = "HTTPS ei ole käytössä. Ota se käyttöön asetuksella \"https\": true ja varmista, että openssl on asennettu.";
    info.replaceChildren();
    return;
  }
  const days = Math.floor((t.not_after * 1000 - Date.now()) / 86400000);
  state.textContent = t.custom
    ? "Käytössä on oma varmenteesi. Sihti lataa sen uudelleen automaattisesti, kun tiedosto vaihtuu."
    : `Sihti uusii varmenteen itse 30 päivää ennen sen vanhenemista ja aina, kun laitteen nimi tai osoite muuttuu.`;
  const rows = [
    ["Voimassa", `${new Date(t.not_after * 1000).toLocaleDateString("fi-FI")} asti (${days} pv)`],
    ["Osoitteet", [...t.names, ...t.ips].join(", ") || "–"],
    ["Sormenjälki", t.fingerprint, "fp"],
  ];
  if (t.ca_fingerprint) rows.push(["Varmentajan sormenjälki", t.ca_fingerprint, "fp"]);
  info.replaceChildren(...rows.flatMap(([k, v, c]) => [el("dt", { text: k }), el("dd", { text: v, class: c || "" })]));
}
$("#tls-renew").addEventListener("click", async (e) => {
  e.target.disabled = true;
  try { await api("/api/tls/renew", { method: "POST" }); flash($("#tls-msg"), "Uusi varmenne otettu käyttöön."); loadTls(); }
  catch (err) { flash($("#tls-msg"), err.message); }
  e.target.disabled = false;
});

$("#settings").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/settings", { method: "POST", body: {
      upstreams: $("#s-upstreams").value.split("\n"),
      block_mode: document.querySelector("input[name=block_mode]:checked")?.value || "null",
      log_retention_days: Number($("#s-retention").value),
      cache_size: Number($("#s-cache").value),
      update_interval_hours: Number($("#s-interval").value),
      log_queries: $("#s-log").checked,
    } });
    flash($("#settings-msg"), "Asetukset tallennettu.");
  } catch (err) { flash($("#settings-msg"), err.message); }
});
$("#pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await api("/api/password", { method: "POST", body: { password: $("#pw-new").value } });
  $("#pw-new").value = "";
  if (r.has_password) { location.reload(); return; }
  flash($("#pw-msg"), "Salasana poistettu.");
  loadSettings();
});
$("#clear-cache").addEventListener("click", async () => { await api("/api/cache/clear", { method: "POST" }); flash($("#maint-msg"), "Välimuisti tyhjennetty."); });
$("#clear-log").addEventListener("click", async () => {
  if (!confirm("Poistetaanko koko kyselyloki pysyvästi?")) return;
  await api("/api/log/clear", { method: "POST" });
  flash($("#maint-msg"), "Kyselyloki poistettu.");
});

boot();
