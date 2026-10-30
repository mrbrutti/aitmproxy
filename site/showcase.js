/* aitmproxy — the feature showcase timeline.
   Reads site/demos/demos.json (written by the demos pipeline) and turns it into a
   Proxyman-style stepper: one numbered timeline step per clip, driving a single muted
   inline video. The active clip autoplays and, when it ends, the timeline advances to the
   next feature; clicking a step jumps to it. Progressive and additive — if the manifest is
   absent or empty the whole section stays hidden and nothing changes. Under reduced motion
   nothing autoplays: the poster shows with native controls. Only the active clip loads, and
   it pauses when the section scrolls off screen, so the page stays light. */
(function () {
  "use strict";

  var host = document.getElementById("showcase");
  if (!host || !window.fetch) return;
  var stepsEl = host.querySelector(".showcase-steps");
  var video = host.querySelector(".showcase-video");
  var capEl = host.querySelector(".showcase-cap");
  if (!stepsEl || !video || !capEl) return;

  var mq = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  var reduce = !!(mq && mq.matches);
  var BASE = "demos/";
  var clips = [], idx = -1, inView = false;

  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
  function pad2(n) { n = String(n); return n.length < 2 ? "0" + n : n; }

  function playActive() {
    if (reduce || !inView || idx < 0) return;
    var p = video.play();
    if (p && p.catch) p.catch(function () { video.controls = true; });
  }

  function activate(i) {
    if (!clips[i]) return;
    idx = i;
    var c = clips[i];
    var btns = stepsEl.querySelectorAll("[role=tab]");
    for (var j = 0; j < btns.length; j++) {
      var on = j === i;
      btns[j].setAttribute("aria-selected", on ? "true" : "false");
      btns[j].tabIndex = on ? 0 : -1;
      btns[j].parentNode.classList.toggle("is-active", on);
      var fill = btns[j].querySelector(".s-bar > i");
      if (fill && !on) fill.style.transform = "scaleX(0)";
    }
    if (reduce) video.classList.remove("is-switching"); else video.classList.add("is-switching");
    video.setAttribute("poster", BASE + c.poster);
    video.loop = reduce;                 /* reduced motion: let a manual play loop; else advance on end */
    video.controls = reduce;
    video.preload = reduce ? "metadata" : "auto";
    video.src = BASE + c.video;
    capEl.textContent = c.caption || c.feature;
    playActive();
  }

  function focusStep(i) {
    var n = clips.length; i = ((i % n) + n) % n;
    var b = stepsEl.querySelectorAll("[role=tab]")[i];
    if (b) { b.focus(); activate(i); }
  }

  function buildSteps() {
    stepsEl.innerHTML = "";
    clips.forEach(function (c, i) {
      var li = document.createElement("li");
      li.className = "showcase-step";
      var btn = document.createElement("button");
      btn.type = "button";
      btn.setAttribute("role", "tab");
      btn.setAttribute("aria-selected", "false");
      btn.tabIndex = -1;
      btn.innerHTML =
        '<span class="s-num">' + pad2(i + 1) + "</span>" +
        '<span class="s-text"><span class="s-feature">' + esc(c.feature) + "</span>" +
        (c.mode ? '<span class="s-mode">' + esc(c.mode) + "</span>" : "") +
        "</span>" +
        '<span class="s-bar" aria-hidden="true"><i></i></span>';
      btn.addEventListener("click", function () { activate(i); });
      btn.addEventListener("keydown", function (e) {
        if (e.key === "ArrowDown" || e.key === "ArrowRight") { e.preventDefault(); focusStep(i + 1); }
        else if (e.key === "ArrowUp" || e.key === "ArrowLeft") { e.preventDefault(); focusStep(i - 1); }
        else if (e.key === "Home") { e.preventDefault(); focusStep(0); }
        else if (e.key === "End") { e.preventDefault(); focusStep(clips.length - 1); }
      });
      li.appendChild(btn);
      stepsEl.appendChild(li);
    });
  }

  /* the active step's progress bar tracks the clip */
  video.addEventListener("timeupdate", function () {
    if (idx < 0) return;
    var li = stepsEl.children[idx]; if (!li) return;
    var fill = li.querySelector(".s-bar > i"); if (!fill) return;
    var d = video.duration || 0;
    fill.style.transform = "scaleX(" + (d ? Math.min(1, (video.currentTime || 0) / d) : 0) + ")";
  });
  function revealVideo() { video.classList.remove("is-switching"); }
  video.addEventListener("loadeddata", revealVideo);
  video.addEventListener("loadedmetadata", revealVideo);
  video.addEventListener("canplay", revealVideo);
  video.addEventListener("error", revealVideo);
  /* when a clip finishes, walk the timeline to the next feature (autoplay path only) */
  video.addEventListener("ended", function () { if (!reduce && inView && clips.length > 1) activate((idx + 1) % clips.length); });

  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (es) {
      es.forEach(function (e) {
        inView = e.isIntersecting;
        if (inView) playActive();
        else if (!video.paused) video.pause();
      });
    }, { threshold: 0.25 }).observe(host);
  } else {
    inView = true;
  }
  if (mq && mq.addEventListener) mq.addEventListener("change", function (e) {
    reduce = e.matches;
    if (idx >= 0) { var cur = idx; idx = -1; activate(cur); }
  });

  fetch(BASE + "demos.json", { cache: "no-cache" }).then(function (r) {
    return r && r.ok ? r.json() : null;
  }).then(function (data) {
    if (!data || !data.clips || !data.clips.length) return;   /* no manifest: stay hidden */
    clips = data.clips;
    buildSteps();
    host.removeAttribute("hidden");
    /* the section was display:none at load, so its scroll-reveals never fired — show them now */
    host.querySelectorAll("[data-reveal]").forEach(function (el) { el.classList.add("in"); });
    activate(0);
  })["catch"](function () { /* no manifest / network / parse error: keep hidden */ });
})();
