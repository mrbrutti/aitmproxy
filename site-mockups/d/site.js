/* Direction D — tiny progressive enhancements. No libraries. */
(function () {
  "use strict";

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

  /* Close the small-screen menu when a link inside it is chosen. */
  var menu = document.querySelector("details.menu");
  if (menu) {
    menu.addEventListener("click", function (e) { if (e.target.closest("a")) menu.removeAttribute("open"); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") menu.removeAttribute("open"); });
  }
})();
