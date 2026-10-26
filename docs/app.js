/* Clean IP Scanner — handbook interactions */
(() => {
  "use strict";

  /* ── language ─────────────────────────────────────────── */
  const root = document.documentElement;
  const toggle = document.getElementById("langToggle");
  /* English is the default; restore only an explicit Persian preference */
  const saved = localStorage.getItem("cis-handbook-lang");
  if (saved === "fa") setLang(saved, false);

  function setLang(lang, persist = true) {
    root.setAttribute("data-lang", lang);
    root.setAttribute("lang", lang === "fa" ? "fa" : "en");
    root.setAttribute("dir", lang === "fa" ? "rtl" : "ltr");
    if (persist) localStorage.setItem("cis-handbook-lang", lang);
  }
  toggle && toggle.addEventListener("click", () => {
    setLang(root.getAttribute("data-lang") === "fa" ? "en" : "fa");
  });

  /* ── reveal on scroll ─────────────────────────────────── */
  const revealEls = document.querySelectorAll(".reveal");
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    });
  }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
  revealEls.forEach((el) => io.observe(el));

  /* ── animated counters ────────────────────────────────── */
  const counters = document.querySelectorAll("[data-count]");
  const cio = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      const el = e.target;
      cio.unobserve(el);
      const target = parseInt(el.getAttribute("data-count"), 10) || 0;
      const suffix = el.getAttribute("data-suffix") || "";
      const dur = 1500;
      const t0 = performance.now();
      const tick = (t) => {
        const p = Math.min(1, (t - t0) / dur);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(target * eased).toLocaleString("en-US") + suffix;
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }, { threshold: 0.6 });
  counters.forEach((el) => cio.observe(el));

  /* ── terminal typing ──────────────────────────────────── */
  const term = document.getElementById("term");
  const LINES = [
    ["$ ", "bun run dev", "cmd"],
    ["▲ ", "Next.js 16 — ready on http://localhost:3000", "ok"],
    ["$ ", "cd mini-services/scan-service && ./run.sh", "cmd"],
    ["✔ ", "scan engine listening on :3003 (socket.io)", "ok"],
    ["[scan] ", "50,796 IPs checked · 270 clean · best 4.0 ms @ 96.78 MB/s", "dim"],
    ["[hunt] ", "google ranges refreshed from 6 live sources", "dim"],
    ["[sched] ", "next fire in 02:00:00 — settings echo attached", "dim"],
  ];
  function colorize(line) {
    const [prefix, body, cls] = line;
    const p = document.createElement("span");
    p.textContent = prefix;
    if (cls === "cmd") p.style.color = "#f59e0b";
    else if (cls === "ok") p.style.color = "#10b981";
    else p.style.color = "#5f7a6e";
    const b = document.createElement("span");
    b.textContent = body;
    if (cls === "dim") b.style.color = "#7fa190";
    return [p, b];
  }
  if (term) {
    let li = 0, ci = 0, spans = [];
    function typeLoop() {
      term.textContent = "";
      li = 0; ci = 0; spans = [];
      typeNext();
    }
    function typeNext() {
      if (li >= LINES.length) { setTimeout(typeLoop, 6000); return; }
      const line = LINES[li];
      if (ci === 0) {
        spans = colorize(line);
        const wrap = document.createElement("div");
        spans.forEach((s) => wrap.appendChild(s));
        term.appendChild(wrap);
      }
      const bodySpan = spans[1];
      if (ci < line[1].length) {
        bodySpan.textContent = line[1].slice(0, ++ci);
        setTimeout(typeNext, 16 + Math.random() * 30);
      } else {
        li++; ci = 0;
        setTimeout(typeNext, line[0] === "$ " ? 350 : 520);
      }
    }
    const tio = new IntersectionObserver((entries) => {
      entries.forEach((e) => { if (e.isIntersecting) { typeLoop(); tio.unobserve(term); } });
    }, { threshold: 0.3 });
    tio.observe(term);
  }

  /* ── copy buttons ─────────────────────────────────────── */
  document.querySelectorAll(".copy").forEach((btn) => {
    btn.addEventListener("click", () => {
      const code = btn.closest(".codecard")?.querySelector("code");
      if (!code) return;
      const text = code.textContent || "";
      const done = () => {
        btn.classList.add("done");
        btn.textContent = "✓";
        setTimeout(() => { btn.classList.remove("done"); btn.textContent = "⧉"; }, 1600);
      };
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
      } else fallbackCopy(text, done);
    });
  });
  function fallbackCopy(text, done) {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (_) {}
    document.body.removeChild(ta);
  }

  /* ── lightbox ─────────────────────────────────────────── */
  const lb = document.getElementById("lightbox");
  if (lb) {
    const lbImg = lb.querySelector("img");
    const lbBtn = lb.querySelector("button");
    document.querySelectorAll(".shot img, .chapter__art img").forEach((img) => {
      img.addEventListener("click", () => {
        lbImg.src = img.src;
        lbImg.alt = img.alt || "";
        lb.hidden = false;
        document.body.style.overflow = "hidden";
      });
    });
    const close = () => { lb.hidden = true; document.body.style.overflow = ""; };
    lbBtn.addEventListener("click", close);
    lb.addEventListener("click", (e) => { if (e.target === lb) close(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !lb.hidden) close(); });
  }

  /* ── progress bar ─────────────────────────────────────── */
  const bar = document.getElementById("progressBar");
  const onScroll = () => {
    const h = document.documentElement;
    const max = h.scrollHeight - h.clientHeight;
    bar.style.width = (max > 0 ? (h.scrollTop / max) * 100 : 0) + "%";
  };
  document.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  /* ── nav scrollspy ────────────────────────────────────── */
  const sections = [...document.querySelectorAll("section.chapter, section#features")];
  const navLinks = [...document.querySelectorAll(".nav__links a")];
  const spy = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      const id = e.target.id;
      navLinks.forEach((a) => {
        const active = a.getAttribute("href") === "#" + id;
        a.style.color = active ? "var(--brand2)" : "";
        a.style.background = active ? "rgba(16,185,129,.1)" : "";
      });
    });
  }, { rootMargin: "-40% 0px -55% 0px" });
  sections.forEach((s) => spy.observe(s));
})();
