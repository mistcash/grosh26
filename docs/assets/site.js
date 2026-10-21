// polyring site: curve toggles, copy buttons, a small Go / shell highlighter,
// the guide's table of contents, the mailing list form, and the hero's Miller
// loop ring. Every page reads without it.
(function () {
  "use strict";

  // Curve toggle: scopes every [data-curve] element inside its target.
  document.querySelectorAll("[data-filter]").forEach(function (group) {
    var scope = document.getElementById(group.getAttribute("data-filter"));
    if (!scope) return;
    group.querySelectorAll("button[data-value]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        scope.setAttribute("data-show", btn.getAttribute("data-value"));
        group.querySelectorAll("button").forEach(function (b) {
          b.setAttribute("aria-pressed", String(b === btn));
        });
      });
    });
  });

  // Theme toggle: system (default), light or dark. The choice is kept in
  // localStorage and applied as data-theme before first paint (see <head>).
  var root = document.documentElement, KEY = "polyring-theme";
  var themeBtns = document.querySelectorAll("[data-theme-set]");
  function markTheme(v) {
    themeBtns.forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-theme-set") === v)); });
  }
  var saved = root.getAttribute("data-theme");
  markTheme(saved === "light" || saved === "dark" ? saved : "system");
  themeBtns.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var v = btn.getAttribute("data-theme-set");
      if (v === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", v);
      try { if (v === "system") localStorage.removeItem(KEY); else localStorage.setItem(KEY, v); } catch (e) {}
      markTheme(v);
      document.dispatchEvent(new Event("polyring:theme"));
    });
  });

  // Highlighting: comments, strings and a few keywords. Works on text nodes
  // only, so nothing in a code block is ever parsed as HTML.
  var GO_BASE = "(\\/\\/[^\\n]*)|(\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`)|\\b(func|return|if|err|nil|type|struct|package|import|for|range|replace|require|module|go)\\b|\\b((?:recursion|solidity|polyring)\\.\\w+)";
  var GO;
  try { GO = new RegExp(GO_BASE + "|(?<![\\w.])(\\d[\\d_]*)(?![\\w.])", "g"); }
  catch (e) { GO = new RegExp(GO_BASE, "g"); } // older engines: no number colouring
  var SH = /(#[^\n]*)|("(?:[^"\\\n]|\\.)*")/g;
  var CLS = ["", "c", "s", "k", "p", "n"];
  document.querySelectorAll("pre code[class*='lang-']").forEach(function (code) {
    var re = code.classList.contains("lang-sh") ? SH : code.classList.contains("lang-text") ? null : GO;
    if (!re) return;
    var src = code.textContent, out = document.createDocumentFragment(), last = 0, m;
    re.lastIndex = 0;
    while ((m = re.exec(src))) {
      if (m.index > last) out.appendChild(document.createTextNode(src.slice(last, m.index)));
      var span = document.createElement("span"), g = 1;
      while (g < m.length && m[g] === undefined) g++;
      span.className = CLS[g] || "k";
      span.textContent = m[0];
      out.appendChild(span);
      last = re.lastIndex;
    }
    out.appendChild(document.createTextNode(src.slice(last)));
    code.textContent = "";
    code.appendChild(out);
  });

  // Copy buttons copy the text exactly as shown.
  function copier(btn, source) {
    var label = btn.textContent;
    btn.addEventListener("click", function () {
      var text = source.textContent.replace(/\n$/, "");
      var done = function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = label; }, 1500);
      };
      var select = function () {
        var range = document.createRange();
        range.selectNodeContents(source);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.textContent = "Press Ctrl/Cmd+C";
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, select);
      } else {
        select();
      }
    });
  }
  document.querySelectorAll(".code").forEach(function (block) {
    var btn = block.querySelector(".copy"), pre = block.querySelector("pre");
    if (btn && pre) copier(btn, pre);
  });
  document.querySelectorAll(".install").forEach(function (row) {
    var btn = row.querySelector("button"), code = row.querySelector("code");
    if (btn && code) copier(btn, code);
  });

  // Guide: mark the step in view in the table of contents.
  var toc = document.querySelectorAll(".toc ol a[href^='#']");
  if (toc.length && "IntersectionObserver" in window) {
    var byId = {};
    toc.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        toc.forEach(function (a) { a.classList.remove("on"); });
        var a = byId[e.target.id];
        if (a) a.classList.add("on");
      });
    }, { rootMargin: "-30% 0px -60% 0px" });
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) io.observe(el);
    });
  }

  // Mailing list: the form posts to Loops on its own; with JS it submits in
  // place and reports the result under the field.
  document.querySelectorAll("form.signup").forEach(function (form) {
    var btn = form.querySelector("button"), msg = form.querySelector(".msg");
    function say(text, cls) { msg.textContent = text; msg.className = "msg" + (cls ? " " + cls : ""); }
    form.addEventListener("submit", function (e) {
      if (!window.fetch) return;
      e.preventDefault();
      btn.disabled = true;
      say("Subscribing…");
      fetch(form.action, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "email=" + encodeURIComponent(form.elements.email.value)
      }).then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (res.ok && data.success) {
            form.reset();
            say("Thanks, you're on the list.", "ok");
          } else if (res.status === 429) {
            say("Too many signups from here. Try again in a minute.", "err");
          } else {
            say(data.message || "Something went wrong. Please try again.", "err");
          }
        });
      }, function () {
        say("Couldn't reach the mailing list. Please try again.", "err");
      }).then(function () { btn.disabled = false; });
    });
  });

  // Hero ring: the 66 signed digits of BN254's Miller loop parameter 6x+2,
  // one tick per loop step (+1 outward, -1 inward, 0 a dot). A sweep walks the
  // loop; when it closes, the inner ring of 12 coefficients (one F_p^12
  // remainder) lights once: every step, one batched check.
  var canvas = document.getElementById("ring");
  if (!canvas || !canvas.getContext) return;
  var NAF = [1,0,-1,0,1,0,0,0,-1,0,-1,0,0,0,-1,0,1,0,-1,0,0,-1,0,0,0,0,0,1,0,0,-1,0,1,0,0,-1,0,0,0,0,-1,0,1,0,0,0,-1,0,-1,0,0,1,0,0,0,-1,0,0,-1,0,1,0,1,0,0,0];
  var N = NAF.length, ctx = canvas.getContext("2d"), size = 0, dpr = 1;
  var still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var STEP_MS = 70, PAUSE = 26; // pause, in steps, after each lap

  // Colours come from the theme tokens, re-read whenever the theme changes.
  var C = { base: "172, 196, 214", glow: "92, 139, 255", head: "#ffffff" };
  function readColors() {
    var cs = getComputedStyle(root);
    C.base = cs.getPropertyValue("--ring-base").trim() || C.base;
    C.glow = cs.getPropertyValue("--ring-glow").trim() || C.glow;
    C.head = cs.getPropertyValue("--ring-head").trim() || C.head;
    if (still) draw(N);
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    size = canvas.clientWidth;
    canvas.width = canvas.height = Math.round(size * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function draw(head) {
    var c = size / 2, R = size * 0.4, lap = N + PAUSE;
    var pos = head % lap, closing = pos >= N ? (pos - N) / PAUSE : -1;
    ctx.clearRect(0, 0, size, size);

    // outer guide circle
    ctx.strokeStyle = "rgba(" + C.base + ",0.16)";
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(c, c, R, 0, Math.PI * 2); ctx.stroke();

    for (var i = 0; i < N; i++) {
      var a = -Math.PI / 2 + (i / N) * Math.PI * 2;
      var cos = Math.cos(a), sin = Math.sin(a);
      // brightness: trailing glow behind the head; whole ring dims while closing
      var age = pos < N ? pos - i : N + 99;
      var glow = age >= 0 && age < 18 ? 1 - age / 18 : 0;
      if (still) glow = 0.35;
      var done = pos >= N || (age >= 0);
      var alpha = 0.22 + (done ? 0.18 : 0) + glow * 0.6;
      var col = glow > 0.05 ? "rgba(" + C.glow + "," + (0.35 + glow * 0.65) + ")" : "rgba(" + C.base + "," + alpha + ")";
      var d = NAF[i];
      if (d === 0) {
        ctx.fillStyle = col;
        ctx.beginPath(); ctx.arc(c + cos * R, c + sin * R, size * 0.006 + glow * 2, 0, Math.PI * 2); ctx.fill();
      } else {
        var len = size * 0.07, r0 = d > 0 ? R : R - len, r1 = d > 0 ? R + len : R;
        ctx.strokeStyle = col;
        ctx.lineWidth = size * 0.007 + glow * 1.5;
        ctx.lineCap = "round";
        ctx.beginPath(); ctx.moveTo(c + cos * r0, c + sin * r0); ctx.lineTo(c + cos * r1, c + sin * r1); ctx.stroke();
      }
    }

    // inner ring: 12 coefficients of the remainder R(x)
    var flash = still ? 0.5 : closing >= 0 ? Math.sin(Math.min(1, closing * 1.6) * Math.PI) : 0;
    var r2 = size * 0.25;
    ctx.strokeStyle = "rgba(" + C.glow + "," + (0.18 + flash * 0.6) + ")";
    ctx.lineWidth = 1 + flash * 1.5;
    ctx.beginPath(); ctx.arc(c, c, r2, 0, Math.PI * 2); ctx.stroke();
    for (var k = 0; k < 12; k++) {
      var b = -Math.PI / 2 + (k / 12) * Math.PI * 2;
      ctx.fillStyle = flash > 0.05 ? "rgba(" + C.glow + "," + (0.5 + flash * 0.5) + ")" : "rgba(" + C.base + ",0.45)";
      ctx.beginPath(); ctx.arc(c + Math.cos(b) * r2, c + Math.sin(b) * r2, size * 0.008 + flash * 2, 0, Math.PI * 2); ctx.fill();
    }

    // head marker
    if (!still && pos < N) {
      var ah = -Math.PI / 2 + (pos / N) * Math.PI * 2;
      ctx.fillStyle = C.head;
      ctx.beginPath(); ctx.arc(c + Math.cos(ah) * R, c + Math.sin(ah) * R, size * 0.011, 0, Math.PI * 2); ctx.fill();
    }
  }

  readColors();
  document.addEventListener("polyring:theme", readColors);
  var mq = window.matchMedia("(prefers-color-scheme: dark)");
  if (mq.addEventListener) mq.addEventListener("change", readColors);
  resize();
  if ("ResizeObserver" in window) new ResizeObserver(function () { resize(); if (still) draw(N); }).observe(canvas);
  if (still) { draw(N); return; }
  var t0 = performance.now();
  (function frame(now) {
    draw((now - t0) / STEP_MS);
    requestAnimationFrame(frame);
  })(t0);
})();
