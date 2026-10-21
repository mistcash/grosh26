// polyring landing page: curve filter, chart tooltips, copy buttons and a
// small Go / shell highlighter. Everything on the page reads without it.
(function () {
  "use strict";

  // Curve filter: one row above the charts, scoping every chart in the section.
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

  // Axis ticks: spread evenly, each label centred on its gridline.
  document.querySelectorAll(".axis .ticks").forEach(function (ticks) {
    var labels = ticks.children, n = labels.length - 1;
    if (n < 1) return;
    ticks.classList.add("pos");
    for (var i = 0; i <= n; i++) labels[i].style.left = (i / n) * 100 + "%";
  });

  // Tooltips: every mark with data-tip gets one on hover and on focus. The
  // values are also printed beside the marks and in the tables, so the
  // tooltip only adds detail.
  var tip = document.createElement("div");
  tip.className = "tip";
  tip.setAttribute("role", "tooltip");
  document.body.appendChild(tip);

  function show(el, x, y) {
    var lines = el.getAttribute("data-tip").split("|");
    tip.textContent = "";
    var head = document.createElement("b");
    head.textContent = lines[0];
    tip.appendChild(head);
    for (var i = 1; i < lines.length; i++) {
      var line = document.createElement("div");
      line.textContent = lines[i];
      tip.appendChild(line);
    }
    var r = tip.getBoundingClientRect();
    var left = Math.min(Math.max(8, x + 14), window.innerWidth - r.width - 8);
    var top = y - r.height - 12;
    if (top < 8) top = y + 18;
    tip.style.left = left + "px";
    tip.style.top = top + "px";
    tip.classList.add("on");
  }
  function hide() { tip.classList.remove("on"); }

  document.querySelectorAll("[data-tip]").forEach(function (el) {
    if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "0");
    el.addEventListener("pointermove", function (e) { show(el, e.clientX, e.clientY); });
    el.addEventListener("pointerleave", hide);
    el.addEventListener("focus", function () {
      var r = el.getBoundingClientRect();
      show(el, r.left + r.width / 2, r.top);
    });
    el.addEventListener("blur", hide);
  });
  window.addEventListener("scroll", hide, { passive: true });

  // Highlighting: comments, strings and a few keywords. Works on text nodes
  // only, so nothing in a code block is ever parsed as HTML.
  var GO = /(\/\/[^\n]*)|("(?:[^"\\\n]|\\.)*"|`[^`]*`)|\b(func|return|if|err|nil|type|struct|package|import|for|range|replace|require|module|go)\b/g;
  var SH = /(#[^\n]*)|("(?:[^"\\\n]|\\.)*")/g;
  document.querySelectorAll("pre code[class*='lang-']").forEach(function (code) {
    var re = code.classList.contains("lang-sh") ? SH : code.classList.contains("lang-text") ? null : GO;
    if (!re) return;
    var src = code.textContent, out = document.createDocumentFragment(), last = 0, m;
    re.lastIndex = 0;
    while ((m = re.exec(src))) {
      if (m.index > last) out.appendChild(document.createTextNode(src.slice(last, m.index)));
      var span = document.createElement("span");
      span.className = m[1] ? "c" : m[2] ? "s" : "k";
      span.textContent = m[0];
      out.appendChild(span);
      last = re.lastIndex;
    }
    out.appendChild(document.createTextNode(src.slice(last)));
    code.textContent = "";
    code.appendChild(out);
  });

  // Copy buttons copy the block's text exactly as shown.
  document.querySelectorAll(".code").forEach(function (block) {
    var btn = block.querySelector(".copy");
    var code = block.querySelector("pre");
    if (!btn || !code) return;
    btn.addEventListener("click", function () {
      var text = code.textContent.replace(/\n$/, "");
      var done = function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () { btn.textContent = "Select and copy"; });
      } else {
        var range = document.createRange();
        range.selectNodeContents(code);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.textContent = "Press Ctrl/Cmd+C";
      }
    });
  });
})();
