"use strict";
// Sihti – käyttöliittymä. Kaikki palvelimelta tuleva teksti asetetaan textContentilla.

const $ = (s) => document.querySelector(s);
const fmt = new Intl.NumberFormat("fi-FI");
const pctFmt = new Intl.NumberFormat("fi-FI", { style: "percent", maximumFractionDigits: 1 });
const STATUS_LABEL = { estetty: "Estetty", sallittu: "Sallittu", valimuisti: "Välimuisti", virhe: "Virhe" };
const REASON_LABEL = { lista: "Estolista", oma: "Oma esto", lauseke: "Lauseke", sallinta: "Oma sallinta", "ylävirta": "Ylävirta ei vastannut" };

// Lyhyt nimi listan osoitteesta: raw.githubusercontent.com/StevenBlack/hosts/master/hosts -> StevenBlack/hosts
function listName(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    const file = parts.at(-1) || "";
    if (/^(raw\.githubusercontent|github)\.com$/.test(u.hostname) && parts.length >= 2) {
      return `${parts[0]}/${parts[1]}` + (file && file !== parts[1] ? `/${file}` : "");
    }
    if (!u.hostname) return file || url;
    return u.hostname + (file ? `/${file}` : "");
  } catch { return url; }
}

// Eston (tai sallinnan) syy luettavana: "Estolista: StevenBlack/hosts", "Oma esto: example.com"
function reasonText(reason, detail) {
  if (!reason) return "";
  const label = REASON_LABEL[reason] || reason;
  if (!detail) return label;
  return `${label}: ${reason === "lista" ? detail.split(" ").map(listName).join(", ") : detail}`;
}
const reasonTitle = (reason, detail) => reason === "lista" && detail ? detail.split(" ").join("\n") : (detail || "");

// "ladataan listoja 1/3 (12 s)" tai "käsitellään listoja (1 min 5 s)"
function progressText(p) {
  if (!p) return "päivitetään…";
  const e = Math.round(p.elapsed), t = e >= 60 ? `${Math.floor(e / 60)} min ${e % 60} s` : `${e} s`;
  return p.phase === "lataus" ? `ladataan listoja ${p.done}/${p.total} (${t})` : `käsitellään listoja (${t})`;
}
const plural = (n, one, many) => `${fmt.format(n)}\u00a0${n === 1 ? one : many}`;  // luku ja sana samalle riville
function durationFmt(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d} pv ${h} t` : h ? `${h} t ${m} min` : `${m} min`;
}

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
  await refreshStatus();   // tila ensin, jotta näkymä tietää esim. käynnissä olevasta listapäivityksestä
  route();
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
let statusReq = null;
function refreshStatus() {   // hitaalla laitteella ei lähetetä uutta pyyntöä edellisen ollessa kesken
  return statusReq || (statusReq = loadStatus().finally(() => (statusReq = null)));
}
async function loadStatus() {
  try { status = await api("/api/status"); } catch { return; }
  const dot = $("#state-dot"), txt = $("#state-text"), btn = $("#toggle");
  dot.className = "dot " + (status.blocking ? "on" : "off");
  if (status.blocking) txt.textContent = "Suodatus päällä";
  else if (status.blocking_enabled && status.pause_until) txt.textContent = "Tauolla klo " + new Date(status.pause_until * 1000).toLocaleTimeString("fi-FI", { hour: "2-digit", minute: "2-digit" }) + " asti";
  else txt.textContent = "Suodatus pois";
  btn.textContent = status.blocking ? "Poista käytöstä" : "Ota käyttöön";
  $("#pause").hidden = !status.blocking;
  if (current === "yleiskuva") { renderHeadline(); renderKpis(); }
  if (current === "listat" && status.lists_updating && !listWait) { listState = listStateFrom(status); waitForLists(); }
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
}

function renderKpis() {
  const s = status;
  const decided = s.passed + s.blocked;
  $("#k-total").textContent = fmt.format(s.total);
  $("#k-total-sub").textContent = plural(s.clients, "laite", "laitetta");
  $("#k-pass").textContent = fmt.format(s.passed);
  $("#k-block").textContent = fmt.format(s.blocked);
  $("#k-pass-pct").textContent = decided ? pctFmt.format(s.passed / decided) : "";
  $("#k-block-pct").textContent = decided ? pctFmt.format(s.blocked / decided) : "";
  $("#k-pass-sub").textContent = plural(s.passed_domains, "eri verkkotunnus", "eri verkkotunnusta");
  $("#k-block-sub").textContent = plural(s.blocked_domains, "eri verkkotunnus", "eri verkkotunnusta");

  const loading = s.lists_updating && !s.domains_on_lists;
  $("#k-lists").textContent = loading ? "ladataan…" : fmt.format(s.domains_on_lists);
  const extra = loading ? [] : [plural(s.lists_enabled, "lista", "listaa") + " käytössä"];
  if (s.custom_deny) extra.push(plural(s.custom_deny, "oma esto", "omaa estoa"));
  if (s.custom_regex) extra.push(plural(s.custom_regex, "lauseke", "lauseketta"));
  if (s.lists_updating) extra.push(progressText(s.lists_progress));
  else if (s.build_error) extra.push("viimeisin päivitys epäonnistui");
  $("#k-lists-sub").textContent = extra.join(" · ");

  // Ohut jakopalkki: läpäisseiden ja estettyjen osuus
  const split = $("#split");
  split.hidden = !decided;
  if (decided) {
    const [ok, no] = split.children;
    ok.style.flexGrow = s.passed; ok.hidden = !s.passed;
    no.style.flexGrow = s.blocked; no.hidden = !s.blocked;
    ok.title = `Läpäisi ${fmt.format(s.passed)} (${pctFmt.format(s.passed / decided)})`;
    no.title = `Jäi sihtiin ${fmt.format(s.blocked)} (${pctFmt.format(s.blocked / decided)})`;
    split.setAttribute("aria-label", `${ok.title}, ${no.title.charAt(0).toLowerCase() + no.title.slice(1)}`);
  }

  const facts = [
    [fmt.format(s.cached), "vastausta välimuistista"],
    [fmt.format(s.errors), "kyselyä epäonnistui"],
    [dateFmt(s.last_update), "listat päivitetty"],
    [durationFmt(s.uptime), "käynnissä"],
  ];
  $("#facts").replaceChildren(...facts.map(([v, k]) => el("div", {}, el("dt", { text: k }), el("dd", { text: v }))));
}

// Yleiskuvan linkit avaavat kyselylokin valmiiksi suodatettuna
function presetLog(status = "", search = "") {
  $("#log-status").value = status;
  $("#log-search").value = search;
}
document.querySelectorAll(".kpi[data-status]").forEach((a) => a.addEventListener("click", () => presetLog(a.dataset.status)));

async function loadOverview() {
  if (status) { renderHeadline(); renderKpis(); }
  const [tl, top] = await Promise.all([api("/api/timeline?hours=24"), api("/api/top?hours=24")]);
  drawChart(tl);
  for (const [id, rows, logStatus] of [["top-blocked", top.blocked, "estetty"], ["top-domains", top.domains, "sallittu"], ["top-clients", top.clients, ""]]) {
    const ol = $("#" + id);
    if (!rows.length) { ol.replaceChildren(el("li", { class: "empty", text: "Ei vielä tietoja." })); continue; }
    const max = rows[0].count;
    ol.replaceChildren(...rows.map((r) => {
      const bar = el("span", { class: "bar" });
      bar.style.width = (r.count / max) * 100 + "%";
      const name = el("a", { class: "name", href: "#loki", text: r.name, onclick: () => presetLog(logStatus, r.name) });
      return el("li", { title: r.name }, bar, name, el("span", { class: "n", text: fmt.format(r.count) }));
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
  if (!rows.length) { body.replaceChildren(el("tr", {}, el("td", { colspan: 8, class: "empty", text: "Ei kyselyjä näillä ehdoilla." }))); return; }
  body.replaceChildren(...rows.map((r) => {
    const tag = el("span", { class: "tag " + r.status, text: STATUS_LABEL[r.status] || r.status });
    const why = el("td", { class: "why", text: reasonText(r.reason, r.detail) });
    if (r.detail) why.title = reasonTitle(r.reason, r.detail);
    const action = r.status === "estetty"
      ? el("button", { class: "linkbtn", text: "Salli", onclick: () => quickRule("allow", r.domain) })
      : el("button", { class: "linkbtn", text: "Estä", onclick: () => quickRule("deny", r.domain) });
    return el("tr", { class: r.status },
      el("td", { text: timeFmt(r.ts) }), el("td", { text: r.client }), el("td", { class: "dom", text: r.domain }),
      el("td", { text: r.qtype }), el("td", {}, tag), why, el("td", { class: "r", text: r.ms ?? "" }), el("td", {}, action));
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
  const why = r.reason ? ` – ${reasonText(r.reason, r.detail)}` : "";
  out.textContent = r.blocked ? `${r.domain} estetään${why}.` : `${r.domain} päästetään läpi${why}.`;
});

/* ---------- estolistat ---------- */
// Päivityksen tila: {updating, progress, build_error}. Seurataan kevyellä rajapinnalla, joka ei
// aja kyselylokin tilastoja (hitaalla laitteella ne kilpailisivat listojen käsittelyn kanssa).
let listState = null;
const listStateFrom = (s) => s && { updating: s.lists_updating, progress: s.lists_progress, build_error: s.build_error };
let listBase = "";
function renderListState() {
  let text = listBase;
  if (listState?.updating) text += ` Päivitys käynnissä: ${progressText(listState.progress)}.`;
  else if (listState?.build_error) text += ` Viimeisin päivitys epäonnistui: ${listState.build_error}`;
  $("#list-summary").textContent = text;
}

async function loadLists(data, state) {
  const lists = data || await api("/api/lists");
  const total = lists.filter((l) => l.enabled).reduce((s, l) => s + (l.count || 0), 0);
  listBase = `${lists.length} listaa, käytössä olevissa yhteensä ${fmt.format(total)} riviä (päällekkäiset lasketaan kerran suodatuksessa).`;
  if (state) listState = state;   // juuri haettu tila muutoksen jälkeen
  else if (!listWait) listState = listStateFrom(status) || listState;   // näkymään tultaessa
  renderListState();
  if (listState?.updating) waitForLists();
  $("#lists").replaceChildren(...lists.map((l) => {
    const cb = el("input", { type: "checkbox", "aria-label": "Käytössä" });
    cb.checked = l.enabled;
    cb.addEventListener("change", async () => listsChanged(await api("/api/lists", { method: "PATCH", body: { url: l.url, enabled: cb.checked } })));
    const meta = el("div", { class: "meta" }, `${fmt.format(l.count || 0)} nimeä · päivitetty ${dateFmt(l.updated)}`);
    if (l.error) meta.append(" · ", el("span", { class: "err", text: "viimeisin lataus epäonnistui: " + l.error }));
    return el("li", { class: l.enabled ? "" : "off" }, cb, el("div", { class: "url", text: l.url }),
      el("button", { class: "linkbtn", text: "Poista", onclick: async () => {
        if (confirm("Poistetaanko lista?")) listsChanged(await api("/api/lists", { method: "DELETE", body: { url: l.url } }));
      } }), meta);
  }));
}
$("#list-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { listsChanged(await api("/api/lists", { method: "POST", body: { url: $("#list-url").value } })); $("#list-url").value = ""; }
  catch (err) { alert(err.message); }
});
$("#list-update").addEventListener("click", async () => {
  await api("/api/lists/update", { method: "POST" });
  listsChanged();
});

// Listojen lataus ja käsittely jatkuvat taustalla: tila päivittyy, kunnes työ on valmis.
async function listsChanged(data) {
  let state;
  try { state = await api("/api/lists/progress"); } catch { /* näytetään ilman tilaa */ }
  loadLists(data, state);
}
let listWait = null;
function waitForLists() {
  if (listWait) return listWait;
  const b = $("#list-update");
  b.disabled = true; b.textContent = "Päivitetään…";
  listWait = (async () => {
    for (;;) {
      await new Promise((r) => setTimeout(r, 1500));
      try { listState = await api("/api/lists/progress"); } catch { break; }
      if (!listState.updating) break;
      if (current === "listat") renderListState();
    }
  })().finally(async () => {
    listWait = null;
    b.disabled = false; b.textContent = "Päivitä listat nyt";
    await refreshStatus();
    listState = listStateFrom(status);
    if (current === "listat") loadLists();
  });
  return listWait;
}

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
  const randomPw = !!s.random_password;
  $("#pw-new").hidden = randomPw;
  $("#pw-form button").hidden = randomPw;
  $("#pw-state").textContent = randomPw
    ? "Salasana vaihtuu satunnaiseksi jokaisella käynnistyksellä. Nykyinen salasana näkyy kontin lokissa: docker logs sihti | grep \"random password\" | tail -n1"
    : s.has_password ? "Salasana on asetettu." : "Salasanaa ei ole asetettu – kuka tahansa lähiverkossa voi muuttaa asetuksia.";
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
    : "Sihti uusii varmenteen itse 30 päivää ennen sen vanhenemista ja aina, kun laitteen nimi tai osoite muuttuu. "
      + "Kun avaat sivun uudella lähiverkko-osoitteella, osoite lisätään varmenteeseen automaattisesti."
      + (t.shared_ca ? " Käytössä on yhteinen varmentaja, joten sama asennus kelpaa kaikkiin Sihti-laitteisiin." : "");
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
