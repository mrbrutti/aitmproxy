/* aitmproxy site — small progressive enhancements. No libraries, no build step.
   Everything here is additive: the page is complete and readable before this runs,
   and nothing stays hidden if it never does (reveals are gated on html.js, set inline). */
(function () {
  "use strict";

  var reduce = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  var hasIO = "IntersectionObserver" in window;

  /* Numbered lines on code viewers (not terminals): wrap each line, CSS counts them. */
  document.querySelectorAll(".code:not(.term) pre > code").forEach(function (code) {
    if (code.querySelector(".cl")) return;
    var lines = code.innerHTML.split("\n");
    // drop a single trailing empty line from a closing newline
    if (lines.length > 1 && lines[lines.length - 1].trim() === "") lines.pop();
    code.innerHTML = lines.map(function (ln) {
      return '<span class="cl"><span class="lc">' + (ln.length ? ln : "&#8203;") + "</span></span>";
    }).join("");
  });

  /* Copy buttons: copy the nearest code/pre text. The check glyph the feedback draws is
     added here, so the markup stays a plain clipboard icon. */
  var SVG = "http://www.w3.org/2000/svg";
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    var svg = btn.querySelector("svg");
    if (svg && !svg.querySelector(".chk")) {
      var chk = document.createElementNS(SVG, "path");
      chk.setAttribute("class", "chk");
      chk.setAttribute("d", "M3.5 8.5 L6.5 11.5 L12.5 4.5");
      svg.appendChild(chk);
    }
    btn.addEventListener("click", function () {
      var scope = btn.closest(".code, .cmd, .pair-row");
      var src = scope && (scope.querySelector("pre") || scope.querySelector("code"));
      if (!src) return;
      var text = src.innerText.replace(/^\$ /gm, "").trim();
      var done = function () {
        btn.removeAttribute("data-done"); void btn.offsetWidth; /* restart the draw on a second click */
        btn.setAttribute("data-done", "");
        clearTimeout(btn._t);
        btn._t = setTimeout(function () { btn.removeAttribute("data-done"); }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        var r = document.createRange(); r.selectNodeContents(src);
        var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        try { document.execCommand("copy"); } catch (e) { /* ignore */ }
        s.removeAllRanges(); done();
      }
    });
  });

  /* On-this-page rail: mark the heading currently in view. */
  var rail = document.querySelector(".rail");
  if (rail && hasIO) {
    var links = Array.prototype.slice.call(rail.querySelectorAll("a[href^='#']"));
    var byId = {};
    links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
    var heads = Object.keys(byId).map(function (id) { return document.getElementById(id); }).filter(Boolean);
    var current = null;
    var set = function (id) {
      if (current === id) return;
      links.forEach(function (a) { a.removeAttribute("aria-current"); });
      if (byId[id]) byId[id].setAttribute("aria-current", "true");
      current = id;
    };
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) set(e.target.id); });
    }, { rootMargin: "0px 0px -70% 0px", threshold: 0 });
    heads.forEach(function (h) { io.observe(h); });
    if (heads.length) set(heads[0].id);
  }

  /* On small screens the docs nav starts collapsed; on wide screens it is always open. */
  var docnav = document.querySelector(".docnav details");
  if (docnav && window.matchMedia) {
    var mq = window.matchMedia("(max-width: 860px)");
    var sync = function () { if (mq.matches) docnav.removeAttribute("open"); else docnav.setAttribute("open", ""); };
    sync();
    if (mq.addEventListener) mq.addEventListener("change", sync);
  }

  /* Entrances: each [data-reveal] rises once as it comes into view (CSS does the motion;
     data-d staggers siblings). Reveal everything at once when there is no observer or no
     motion, and as a last resort reveal anything already on screen after a moment, so a
     missed observation can never leave content hidden. */
  var reveals = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));
  function revealAll() { reveals.forEach(function (el) { el.classList.add("in"); }); }
  if (reveals.length && hasIO && !reduce) {
    var ro = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); ro.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    reveals.forEach(function (el) { ro.observe(el); });
    setTimeout(function () {
      var vh = window.innerHeight || document.documentElement.clientHeight;
      reveals.forEach(function (el) {
        if (el.classList.contains("in")) return;
        var r = el.getBoundingClientRect();
        if (r.top < vh && r.bottom > 0) el.classList.add("in");
      });
    }, 2500);
  } else {
    revealAll();
  }

  /* Live dots: the rings on captions and fragment bars run only while on screen. */
  var dots = Array.prototype.slice.call(document.querySelectorAll(".live, .ui-bar .dot"));
  if (dots.length && hasIO && !reduce) {
    var lo = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { e.target.classList.toggle("on", e.isIntersecting); });
    }, { threshold: 0 });
    dots.forEach(function (d) { lo.observe(d); });
  }

  /* Close the small-screen menu when a link inside it is chosen. */
  var menu = document.querySelector("details.menu");
  if (menu) {
    menu.addEventListener("click", function (e) { if (e.target.closest("a")) menu.removeAttribute("open"); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") menu.removeAttribute("open"); });
  }

  /* Download table: fetch downloads.json (the release manifest) and render one row
     per asset into [data-downloads]. Progressive enhancement — if the manifest is
     absent or fails to load or parse, the container stays hidden and the static
     Homebrew / build-from-source instructions remain the download path. On failure
     we change nothing and say nothing (no console output). */
  var dlHost = document.querySelector("[data-downloads]");
  if (dlHost && window.fetch) {
    var td = function (text) {
      var cell = document.createElement("td");
      cell.textContent = text == null ? "" : String(text);
      return cell;
    };
    var shortSha = function (sha) {
      var s = sha == null ? "" : String(sha);
      return s.length > 12 ? s.slice(0, 12) + "…" : s;
    };
    var renderDownloads = function (data) {
      if (!data || !data.assets || !data.assets.length) return;
      var ui = document.createElement("div");
      ui.className = "ui";
      var table = document.createElement("table");
      table.className = "flows";
      var thead = document.createElement("thead");
      var hr = document.createElement("tr");
      ["Platform", "Arch", "Format", "SHA-256", "Download"].forEach(function (h) {
        var th = document.createElement("th");
        th.textContent = h;
        hr.appendChild(th);
      });
      thead.appendChild(hr);
      table.appendChild(thead);
      var tbody = document.createElement("tbody");
      data.assets.forEach(function (a) {
        var tr = document.createElement("tr");
        tr.appendChild(td(a.platform));
        tr.appendChild(td(a.arch));
        tr.appendChild(td(a.format));
        var shaCell = document.createElement("td");
        var code = document.createElement("code");
        code.textContent = shortSha(a.sha256);
        shaCell.appendChild(code);
        tr.appendChild(shaCell);
        var dlCell = document.createElement("td");
        if (a.url) {
          var link = document.createElement("a");
          link.href = a.url;
          link.textContent = a.name || a.url;
          link.setAttribute("rel", "noopener");
          dlCell.appendChild(link);
        } else {
          dlCell.textContent = a.name || "";
        }
        tr.appendChild(dlCell);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      ui.appendChild(table);
      dlHost.appendChild(ui);
      dlHost.removeAttribute("hidden");
    };
    try {
      window.fetch("downloads.json", { cache: "no-cache" }).then(function (res) {
        return res && res.ok ? res.json() : null;
      }).then(function (data) {
        if (data) renderDownloads(data);
      })["catch"](function () { /* no manifest / network / parse error: keep the fallback */ });
    } catch (e) { /* fetch threw synchronously: keep the fallback */ }
  }
})();
