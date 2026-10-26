/* Clean IP Scanner — offline demo interactions (no engine, sample data only) */
(() => {
  "use strict";

  const root = document.documentElement;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const fmt = (n) => n.toLocaleString("en-US");

  /* ── tiny i18n for dynamic strings ──────────────────── */
  let lang = localStorage.getItem("cis-demo-lang") || "fa";
  const T = {
    fa: {
      copied: "IP کپی شد", starAdd: "به علاقه‌مندی‌ها اضافه شد", starRm: "از علاقه‌مندی‌ها حذف شد",
      scanDone: (n) => `اسکن دمو تکمیل شد — ${n} IP پاک اضافه شد`,
      huntDone: (n) => `شکار دمو تکمیل شد — ${n} IP از رنج گوگل پیدا شد`,
      warpDone: "اسکن WARP دمو: ۰ اندپوینت زنده — UDP در این محیط بلاک است",
      tgErr: "خطا ۵۰۲ — توکن تلگرام نمایشی است",
      notifOk: "اعلان واقعی ارسال شد (این بخش در دمو هم واقعی است)",
      notifDeny: "اجازهٔ اعلان داده نشد",
      notifBody: "پیدا شد: ۵ IP پاک جدید — بهترین تأخیر ۴ میلی‌ثانیه",
      notifTitle: "Clean IP Scanner",
      favEmpty: "چیزی ستاره‌دار نشده — از جدول نتایج ستاره بزن",
      favSub: (n) => `${n} ستاره — روی ستاره بزن تا حذف شود`,
      showAll: (n) => `نمایش همهٔ ${n} ردیف`, showLess: (n) => `نمایش ۱۲ ردیف برتر از ${n}`,
      viewOnly: "در دمو فقط نمایش است — برای اعمال، اپ را محلی اجرا کن",
      demoNotif: "اعلان تست دمو — اتصال موتور برقرار است (شبیه‌سازی)",
    },
    en: {
      copied: "IP copied", starAdd: "Added to favorites", starRm: "Removed from favorites",
      scanDone: (n) => `Demo scan finished — ${n} clean IPs added`,
      huntDone: (n) => `Demo hunt finished — ${n} IPs found from Google ranges`,
      warpDone: "Demo WARP sweep: 0 alive endpoints — UDP is blocked in this environment",
      tgErr: "502 error — the Telegram token is a mock",
      notifOk: "Real notification sent (this part is real even in the demo)",
      notifDeny: "Notification permission denied",
      notifBody: "Found: 5 new clean IPs — best latency 4 ms",
      notifTitle: "Clean IP Scanner",
      favEmpty: "Nothing starred yet — star rows from the results table",
      favSub: (n) => `${n} starred — tap the star to remove`,
      showAll: (n) => `Show all ${n} rows`, showLess: (n) => `Show top 12 of ${n}`,
      viewOnly: "View-only in the demo — self-host the app to apply",
      demoNotif: "Demo test notification — engine link established (simulated)",
    },
  };
  const t = (k, ...a) => {
    const v = T[lang][k];
    return typeof v === "function" ? v(...a) : v;
  };

  /* ── toasts ─────────────────────────────────────────── */
  const toasts = $("#toasts");
  function toast(msg, kind = "ok") {
    const el = document.createElement("div");
    el.className = "toast" + (kind === "warn" ? " toast--warn" : kind === "err" ? " toast--err" : "");
    el.textContent = msg;
    toasts.appendChild(el);
    setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 350); }, 2600);
  }

  /* ── language / theme ───────────────────────────────── */
  function applyLang() {
    root.dataset.lang = lang;
    root.lang = lang;
    root.dir = lang === "fa" ? "rtl" : "ltr";
    $("#langMini").textContent = lang === "fa" ? "EN" : "فا";
    localStorage.setItem("cis-demo-lang", lang);
    renderAll();
  }
  $("#langBtn").addEventListener("click", () => { lang = lang === "fa" ? "en" : "fa"; applyLang(); });

  const savedTheme = localStorage.getItem("cis-demo-theme") || "dark";
  root.dataset.theme = savedTheme;
  $("#themeBtn").addEventListener("click", () => {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    localStorage.setItem("cis-demo-theme", next);
  });

  /* ── tabs (with arrow-key support) ──────────────────── */
  const tabs = $$(".tab");
  function selectTab(tab) {
    tabs.forEach((b) => {
      const on = b === tab;
      b.classList.toggle("is-active", on);
      b.setAttribute("aria-selected", String(on));
      const panel = document.getElementById(b.getAttribute("aria-controls"));
      if (panel) panel.hidden = !on;
    });
  }
  tabs.forEach((b) => b.addEventListener("click", () => selectTab(b)));
  $(".tabs").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const dir = (lang === "fa" ? -1 : 1) * (e.key === "ArrowRight" ? 1 : -1);
    const nx = tabs[(i + dir + tabs.length) % tabs.length];
    nx.focus(); selectTab(nx); e.preventDefault();
  });

  /* ── seed data (sample only) ────────────────────────── */
  const GEO = {
    nl: ["هلند", "Netherlands"], us: ["آمریکا", "United States"], de: ["آلمان", "Germany"],
    fi: ["فنلاند", "Finland"], tw: ["تایوان", "Taiwan"], sg: ["سنگاپور", "Singapore"],
    ie: ["ایرلند", "Ireland"], jp: ["ژاپن", "Japan"], br: ["برزیل", "Brazil"], in: ["هند", "India"],
  };
  const RAW = [
    ["34.12.183.71", 4.0, 96.78, "nl"], ["34.12.183.72", 5.2, 92.4, "nl"], ["142.250.95.14", 8.1, 88.3, "us"],
    ["216.58.212.100", 9.4, 85.1, "de"], ["172.217.16.14", 11.7, 81.9, "nl"], ["142.250.185.78", 13.2, 79.4, "tw"],
    ["74.125.24.99", 15.6, 74.2, "us"], ["64.233.177.101", 17.3, 71.8, "us"], ["35.190.247.1", 19.8, 69.5, "sg"],
    ["172.217.21.238", 21.5, 66.2, "ie"], ["142.250.74.110", 23.9, 63.8, "us"], ["216.239.34.21", 26.4, 61.5, "us"],
    ["34.117.59.81", 28.2, 58.9, "de"], ["142.250.4.139", 31.6, 55.4, "jp"], ["74.125.68.94", 34.8, 52.7, "us"],
    ["64.233.162.83", 37.1, 49.3, "br"], ["172.217.30.4", 40.5, 46.8, "sg"], ["35.244.222.6", 43.2, 43.5, "in"],
    ["142.250.203.100", 46.9, 40.2, "tw"], ["216.58.214.67", 49.4, 37.6, "nl"], ["34.98.82.131", 52.7, 34.1, "us"],
    ["64.233.164.99", 56.3, 31.8, "ie"], ["172.217.17.14", 59.8, 28.4, "de"], ["142.251.36.14", 62.4, 25.9, "jp"],
    ["216.58.196.78", 65.1, 22.3, "sg"], ["34.64.4.12", 68.7, 19.8, "tw"], ["142.250.200.36", 71.2, 17.4, "us"],
    ["74.125.130.94", 74.6, 14.9, "us"], ["64.233.173.87", 77.3, 12.6, "br"], ["172.217.23.99", 80.9, 10.2, "ie"],
    ["35.201.97.1", 83.4, 8.7, "in"], ["142.250.197.14", 86.8, 6.3, "nl"], ["216.58.198.35", 91.5, 4.1, "de"],
  ];
  let ips = RAW.map(([ip, lat, down, g]) => ({
    ip, lat, down, up: +(down * 0.31).toFixed(1), geo: GEO[g], src: "google", starred: false,
  }));
  const POOL = [
    ["34.141.2.19", "nl"], ["34.150.77.40", "sg"], ["142.251.5.109", "us"], ["216.239.32.108", "us"],
    ["172.253.114.139", "de"], ["74.125.140.99", "us"], ["64.233.186.99", "br"], ["142.250.31.14", "jp"],
  ].map(([ip, g]) => ({ ip, geo: GEO[g], src: "google" }));

  const HIST = [
    { when: ["امروز — ۱۴:۲۰", "Today — 14:20"], preset: ["گوگل کلاد", "Google Cloud"], cands: 12632, clean: 24, dur: "3m 41s" },
    { when: ["دیروز — ۲۲:۰۵", "Yesterday — 22:05"], preset: ["وب کلاد", "Web CDN"], cands: 15204, clean: 6, dur: "5m 12s" },
    { when: ["۳ روز پیش — ۱۱:۳۲", "3 days ago — 11:32"], preset: ["گوگل کلاد", "Google Cloud"], cands: 22960, clean: 2, dur: "7m 02s" },
    { when: ["۵ روز پیش — ۰۹:۱۴", "5 days ago — 09:14"], preset: ["سراسری", "Worldwide"], cands: 31884, clean: 1, dur: "9m 30s" },
  ];
  const CONF = [
    { name: ["گوگل سریع", "Google fast"], preset: ["گوگل کلاد", "Google Cloud"], port: ":443", tag: ["پیش‌فرض", "Default"] },
    { name: ["وب پایدار", "Web steady"], preset: ["وب کلاد", "Web CDN"], port: ":8443", tag: ["ذخیره‌شده", "Saved"] },
    { name: ["بررسی شبانه", "Nightly sweep"], preset: ["سراسری", "Worldwide"], port: ":993", tag: ["زمان‌بندی", "Scheduled"] },
  ];

  let stats = { scans: 4, ipsScanned: 50796, clean: 33 };
  ips.find((r) => r.ip === "34.12.183.71").starred = true;
  ips.find((r) => r.ip === "142.250.95.14").starred = true;
  ips.find((r) => r.ip === "216.58.212.100").starred = true;

  /* ── stats ──────────────────────────────────────────── */
  function renderStats() {
    $("#statScans").textContent = fmt(stats.scans);
    $("#statIps").textContent = fmt(stats.ipsScanned);
    $("#statClean").textContent = fmt(stats.clean);
    $("#resCount").textContent = fmt(ips.length);
  }

  /* ── results table ──────────────────────────────────── */
  let showAll = false;
  let query = "";
  function latClass(v) { return v < 15 ? "lat--g" : v < 40 ? "lat--t" : v < 80 ? "lat--a" : "lat--r"; }

  function renderResults() {
    const sorted = [...ips].sort((a, b) => a.lat - b.lat);
    const filtered = query ? sorted.filter((r) => r.ip.includes(query)) : sorted;
    const shown = showAll || query ? filtered : filtered.slice(0, 12);
    $("#resBody").innerHTML = shown.map((r, i) => `
      <tr data-ip="${r.ip}">
        <td>${i + 1}</td>
        <td><span class="ip">${r.ip}</span> ${r.src === "hunt" ? '<span class="pill">hunt</span>' : ""}</td>
        <td><span class="lat ${latClass(r.lat)}">${r.lat.toFixed(1)} ms</span></td>
        <td>${r.down.toFixed(1)} <small>MB/s</small></td>
        <td class="hide-sm">${(r.down + r.up).toFixed(1)} <small>MB/s</small></td>
        <td class="hide-sm geo">${r.geo[lang === "fa" ? 0 : 1]}</td>
        <td><span class="rowact">
          <button class="rbtn rbtn--copy" type="button" aria-label="copy ${r.ip}"><svg class="ic"><use href="#i-copy"/></svg></button>
          <button class="rbtn rbtn--star${r.starred ? " on" : ""}" type="button" aria-label="star ${r.ip}"><svg class="ic"><use href="#i-star"/></svg></button>
        </span></td>
      </tr>`).join("") || `<tr><td colspan="7"><div class="empty">…</div></td></tr>`;
    $("#resCount").textContent = fmt(filtered.length);
    const btn = $("#showAll");
    btn.textContent = showAll && !query ? t("showLess", fmt(filtered.length)) : t("showAll", fmt(filtered.length));
  }

  $("#showAll").addEventListener("click", () => { showAll = !showAll; renderResults(); });
  $("#searchInput").addEventListener("input", (e) => { query = e.target.value.trim(); renderResults(); });

  document.addEventListener("click", (e) => {
    const holder = e.target.closest("[data-ip]");
    if (!holder) return;
    const ip = holder.dataset.ip;
    if (e.target.closest(".rbtn--copy")) return copyIp(ip);
    if (e.target.closest(".rbtn--star")) {
      const row = ips.find((r) => r.ip === ip);
      row.starred = !row.starred;
      toast(row.starred ? t("starAdd") : t("starRm"), row.starred ? "ok" : "warn");
      renderResults(); renderFavs();
    }
  });

  function copyIp(ip) {
    const done = () => toast(t("copied"));
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(ip).then(done).catch(() => fallbackCopy(ip, done));
    else fallbackCopy(ip, done);
  }
  function fallbackCopy(text, done) {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (_) {}
    document.body.removeChild(ta); done();
  }

  /* ── history / favorites / configs ──────────────────── */
  function renderHistory() {
    $("#historyList").innerHTML = HIST.map((h) => `
      <div class="row">
        <div class="row__main">
          <span class="row__t">${h.when[lang === "fa" ? 0 : 1]}</span>
          <span class="row__s">${fmt(h.cands)} <span data-t="cands"></span> · <span class="ok">${fmt(h.clean)}</span> <span data-t="clean"></span></span>
        </div>
        <span class="row__chips">
          <span class="chip">${h.preset[lang === "fa" ? 0 : 1]}</span>
          <span class="chip" dir="ltr">⏱ ${h.dur}</span>
        </span>
      </div>`).join("");
    $$("#historyList [data-t='cands']").forEach((el) => { el.textContent = lang === "fa" ? "کاندید" : "candidates"; });
    $$("#historyList [data-t='clean']").forEach((el) => { el.textContent = lang === "fa" ? "پاک" : "clean"; });
  }

  function renderFavs() {
    const favs = ips.filter((r) => r.starred);
    $("#favCount").textContent = fmt(favs.length);
    const box = $("#favList");
    if (!favs.length) {
      box.innerHTML = `<div class="empty">${t("favEmpty")}</div>`;
      return;
    }
    box.innerHTML = favs.map((r) => `
      <div class="row" data-ip="${r.ip}">
        <div class="row__main">
          <span class="ip">${r.ip}</span>
          <span class="row__s"><span class="lat ${latClass(r.lat)}">${r.lat.toFixed(1)} ms</span> · ${r.down.toFixed(1)} MB/s · ${r.geo[lang === "fa" ? 0 : 1]}</span>
        </div>
        <span class="rowact">
          <button class="rbtn rbtn--copy" type="button" aria-label="copy"><svg class="ic"><use href="#i-copy"/></svg></button>
          <button class="rbtn rbtn--star on" type="button" aria-label="unstar"><svg class="ic"><use href="#i-star"/></svg></button>
        </span>
      </div>`).join("");
    box.setAttribute("aria-label", t("favSub", favs.length));
  }

  function renderConfigs() {
    $("#configsList").innerHTML = CONF.map((c) => `
      <div class="row">
        <div class="row__main">
          <span class="row__t">${c.name[lang === "fa" ? 0 : 1]}</span>
          <span class="row__s">${c.preset[lang === "fa" ? 0 : 1]} · <span dir="ltr">${c.port}</span></span>
        </div>
        <span class="row__chips"><span class="chip chip--brand">${c.tag[lang === "fa" ? 0 : 1]}</span></span>
      </div>`).join("");
  }

  function renderAll() { renderStats(); renderResults(); renderHistory(); renderFavs(); renderConfigs(); }

  /* ── live dashboard helpers ─────────────────────────── */
  const phaseChip = $("#phaseChip");
  function setPhase(fa, en, kind = "") {
    phaseChip.className = "chip" + (kind ? " chip--" + kind : "");
    phaseChip.innerHTML = `<span class="t-fa">${fa}</span><span class="t-en">${en}</span>`;
  }
  function log(text, cls = "dim") {
    const feed = $("#logFeed");
    const line = document.createElement("div");
    line.className = "term__line fresh";
    const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
    line.innerHTML = `<span class="term__p ${cls}">[${ts}] </span><span class="term__b"></span>`;
    line.lastElementChild.textContent = text;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
    while (feed.children.length > 40) feed.firstChild.remove();
  }
  function setBar(p) {
    $("#scanFill").style.width = p + "%";
    $("#scanBar").setAttribute("aria-valuenow", String(p));
  }
  function setMetrics(tested, clean) {
    $("#mTested").textContent = fmt(tested);
    $("#mClean").textContent = fmt(clean);
    $("#mRate").textContent = tested ? ((clean / tested) * 100).toFixed(2) + "%" : "—";
    $("#mBest").textContent = ips.length ? Math.min(...ips.map((r) => r.lat)).toFixed(1) + " ms" : "—";
  }

  /* ── demo scan simulation ───────────────────────────── */
  const STEPS = [
    { p: 6, d: 650, ph: ["اتصال به منابع رنج…", "Connecting to range sources…"], log: "[discover] fetching google ranges from 6 sources" },
    { p: 18, d: 850, ph: ["جمع‌آوری کاندیدها…", "Collecting candidates…"], log: "[discover] 12,632 candidates generated from CIDR" },
    { p: 36, d: 1050, ph: ["پینگ دستهٔ اول…", "Probing batch 1…"], log: "[scan] probing 2,048 IPs on :443 (concurrency 256)" },
    { p: 56, d: 1100, ph: ["اعتبارسنجی TCP…", "Validating TCP…"], log: "[scan] 118 responsive — validating TLS handshake" },
    { p: 74, d: 1000, ph: ["تست سرعت دانلود…", "Speed testing…"], log: "[speed] downloading 4MB probes from 6 finalists" },
    { p: 90, d: 800, ph: ["رتبه‌بندی نتایج…", "Ranking results…"], log: "[scan] ranking by latency + throughput" },
    { p: 100, d: 500, ph: ["تکمیل شد", "Finished"], log: "[scan] done in 00:07" },
  ];
  let scanning = false;
  const scanBtn = $("#startScan");

  scanBtn.addEventListener("click", () => {
    if (scanning) return;
    scanning = true;
    scanBtn.disabled = true;
    setMetrics(0, 0);
    let tested = 0;
    const testedTicker = setInterval(() => {
      tested = Math.min(tested + 380 + Math.floor(Math.random() * 500), 12632);
      setMetrics(tested, tested > 4000 ? Math.floor(tested / 2400) : 0);
    }, 140);

    const take = POOL.splice(0, 5).map((p) => ({
      ...p,
      lat: +(4 + Math.random() * 66).toFixed(1),
      down: +(30 + Math.random() * 60).toFixed(1),
      starred: false,
    }));
    take.forEach((r) => (r.up = +(r.down * 0.31).toFixed(1)));

    let i = 0;
    (function step() {
      const s = STEPS[i];
      setPhase(s.ph[0], s.ph[1], i === STEPS.length - 1 ? "ok" : "demo");
      log(s.log, i === 0 ? "ok" : "dim");
      setBar(s.p);
      if (i === 4) {
        ips.push(...take);
        stats.clean += take.length;
        renderResults();
        setMetrics(12632, tested > 4000 ? Math.floor(tested / 2400) + take.length : take.length);
        log(`[scan] ${take.length} clean IPs found — best ${Math.min(...take.map((r) => r.lat)).toFixed(1)} ms`, "ok");
      }
      i++;
      if (i < STEPS.length) return setTimeout(step, s.d);
      clearInterval(testedTicker);
      setMetrics(12632, take.length + 0);
      setPhase("آماده", "Idle");
      stats.scans += 1;
      stats.ipsScanned += 12632;
      HIST.unshift({ when: [lang === "fa" ? "همین حالا" : "Just now"], preset: ["گوگل کلاد", "Google Cloud"], cands: 12632, clean: take.length, dur: "0m 07s" });
      renderStats(); renderHistory();
      toast(t("scanDone", take.length));
      scanBtn.disabled = false;
      scanning = false;
      if (typeof Notification !== "undefined" && Notification.permission === "granted") {
        try { new Notification(t("notifTitle"), { body: t("notifBody") }); } catch (_) {}
      }
      setTimeout(() => setBar(0), 1400);
    })();
  });

  /* ── demo hunt ──────────────────────────────────────── */
  const huntBtn = $("#startHunt");
  huntBtn.addEventListener("click", () => {
    if (huntBtn.disabled) return;
    huntBtn.disabled = true;
    setPhase("شکار رنج گوگل…", "Hunting Google ranges…", "demo");
    log("[hunt] refreshing 6 range sources", "ok");
    let step = 0;
    const iv = setInterval(() => {
      step++;
      setBar(step * 25);
      log(["[hunt] parsing dns.google ranges", "[hunt] probing 512 candidates on :8443", "[hunt] 2 healthy IPs verified", "[hunt] hunt finished — journal saved"][step - 1]);
      if (step === 3) {
        const extra = POOL.splice(0, 2).map((p) => ({
          ...p, src: "hunt",
          lat: +(8 + Math.random() * 40).toFixed(1),
          down: +(35 + Math.random() * 45).toFixed(1), starred: false,
        }));
        extra.forEach((r) => (r.up = +(r.down * 0.31).toFixed(1)));
        ips.push(...extra);
        stats.clean += extra.length;
        renderResults();
        log(`[hunt] ${extra.length} IPs added to results`, "ok");
      }
      if (step >= 4) {
        clearInterval(iv);
        setPhase("آماده", "Idle");
        stats.ipsScanned += 512;
        renderStats();
        toast(t("huntDone", 2));
        huntBtn.disabled = false;
        setTimeout(() => setBar(0), 1400);
      }
    }, 900);
  });

  /* ── warp sweep ─────────────────────────────────────── */
  const warpBtn = $("#warpBtn");
  warpBtn.addEventListener("click", () => {
    if (warpBtn.disabled) return;
    warpBtn.disabled = true;
    log("[warp] sweeping 640 endpoints over UDP", "dim");
    setTimeout(() => {
      $("#warpTested").textContent = fmt((parseInt($("#warpTested").textContent.replace(/,/g, ""), 10) || 0) + 640);
      $("#warpAlive").textContent = "0";
      log("[warp] 0 alive — UDP egress looks blocked here", "ok");
      toast(t("warpDone"), "warn");
      warpBtn.disabled = false;
    }, 2200);
  });

  /* ── integrations ───────────────────────────────────── */
  $("#tgBtn").addEventListener("click", () => toast(t("tgErr"), "err"));
  $("#notifyBtn").addEventListener("click", async () => {
    if (typeof Notification === "undefined") return toast(t("demoNotif"));
    try {
      const perm = Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
      if (perm === "granted") {
        new Notification(t("notifTitle"), { body: t("demoNotif") });
        toast(t("notifOk"));
      } else toast(t("notifDeny"), "warn");
    } catch (_) { toast(t("demoNotif")); }
  });

  /* ── boot ───────────────────────────────────────────── */
  applyLang();
  setMetrics(12632, 24);
  log("[engine] demo mode — connect the real engine via `./run.sh` (see setup guide)", "ok");
})();
