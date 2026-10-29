/* Direction D — tiny progressive enhancements. No libraries. */
(function () {
  "use strict";

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

  /* Copy buttons: copy the nearest code/pre text. */
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var scope = btn.closest(".code, .cmd, .pair-row");
      var src = scope && (scope.querySelector("pre") || scope.querySelector("code"));
      if (!src) return;
      var text = src.innerText.replace(/^\$ /gm, "").trim();
      var done = function () {
        btn.setAttribute("data-done", "");
        clearTimeout(btn._t);
        btn._t = setTimeout(function () { btn.removeAttribute("data-done"); }, 1400);
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
  if (rail && "IntersectionObserver" in window) {
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

  /* Subtle reveal-on-scroll. Content is visible without JS; this only adds the entrance. */
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var reveals = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));
  if (reveals.length && "IntersectionObserver" in window && !reduce) {
    var ro = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); ro.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    reveals.forEach(function (el) { ro.observe(el); });
  } else {
    reveals.forEach(function (el) { el.classList.add("in"); });
  }

  /* Hero wire: a live, looping scene. A request arrives and is held & armed,
     then resumed; it completes 200. Pauses off screen; static under reduced motion. */
  (function () {
    var wire = document.querySelector(".hero .wire");
    if (!wire) return;
    var held = wire.querySelector(".held");
    var stateEl = wire.querySelector(".state");
    if (!held || !stateEl) return;
    function set(phase, st, txt) { wire.setAttribute("data-phase", phase); held.setAttribute("data-state", st); stateEl.textContent = txt; }
    if (reduce) { set("held", "armed", "armed"); return; }
    // [phase, held-state, badge text, ms]
    var steps = [["arrive", "", "—", 1300], ["held", "armed", "armed", 2600], ["resume", "armed", "resuming…", 1150], ["done", "done", "200", 2000]];
    var timer = null, running = false;
    function step(i) {
      var s = steps[i]; set(s[0], s[1], s[2]);
      timer = setTimeout(function () { if (i + 1 < steps.length) step(i + 1); else cycle(); }, s[3]);
    }
    function cycle() {
      wire.removeAttribute("data-anim"); set("reset", "", "—");
      requestAnimationFrame(function () { requestAnimationFrame(function () { wire.setAttribute("data-anim", ""); step(0); }); });
    }
    function start() { if (running) return; running = true; cycle(); }
    function stop() { running = false; clearTimeout(timer); }
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (es) { es.forEach(function (e) { if (e.isIntersecting) start(); else stop(); }); }, { threshold: 0.25 }).observe(wire);
    }
    start();
  })();

  /* Close the small-screen menu when a link inside it is chosen. */
  var menu = document.querySelector("details.menu");
  if (menu) {
    menu.addEventListener("click", function (e) { if (e.target.closest("a")) menu.removeAttribute("open"); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") menu.removeAttribute("open"); });
  }
})();
