/* aitmproxy — the introduction. Once per session, the site opens on a blank page in its
   own paper colour (html.intro-on::after, set from the inline <head> script) and the mark
   forms alone: the severed wire gathers from particles while a comet draws it, the comet
   lands in the gap and ignites it amber. Then the page lifts from under the mark and the
   site fades in. On the home page the mark flies into the hero and becomes the wire scene
   itself — wire.js takes over the moment the two coincide. Elsewhere it simply lifts.

   Any key, click, wheel, touch or scroll skips it. A hard timer ends it regardless, and
   the stylesheet releases the overlay and the page on its own at ~4s, so nothing here can
   ever be left covering the site. Under reduced motion it never runs. */
(function () {
  "use strict";
  var html = document.documentElement;
  if (!html.classList.contains("intro-on")) return;

  var done = false, lifted = false, detail = { morphed: false, skipped: false };
  function reveal(skip) {
    if (lifted) return; lifted = true;
    if (skip) html.classList.add("intro-skip");
    html.classList.add("intro-lift"); html.classList.add("intro-reveal");
  }
  function handoff() {
    window.aitmIntro = detail;
    try { window.dispatchEvent(new CustomEvent("aitm:intro", { detail: detail })); } catch (e) {
      var ev = document.createEvent("Event"); ev.initEvent("aitm:intro", false, false); ev.detail = detail; window.dispatchEvent(ev);
    }
  }
  function finish(skip) {
    if (done) return; done = true;
    if (skip) detail.skipped = true;
    reveal(skip || !detail.morphed);
    handoff();
    fadeOut = performance.now();
    setTimeout(function () {
      html.classList.add("intro-done");
      if (raf) cancelAnimationFrame(raf); raf = 0;
      if (cv && cv.parentNode) cv.parentNode.removeChild(cv);
    }, 420);
  }

  /* skip on any intent to use the page; the overlay lets pointers through, so a blind click
     during the introduction is swallowed here rather than reaching a link it cannot see */
  function skip() { if (!done) finish(true); }
  ["keydown", "pointerdown", "mousedown", "touchstart", "wheel"].forEach(function (ev) { window.addEventListener(ev, skip, { passive: true }); });
  var guard = function (e) { if (!lifted) { e.preventDefault(); e.stopPropagation(); } window.removeEventListener("click", guard, true); };
  window.addEventListener("click", guard, true);
  setTimeout(function () { window.addEventListener("scroll", skip, { passive: true }); }, 350);
  /* the hard ceiling: whatever happens, the site shows */
  setTimeout(function () { finish(false); }, 3400);

  /* ── the canvas ────────────────────────────────────────────── */
  var cv = document.createElement("canvas"), ctx = null;
  try { ctx = cv.getContext("2d"); } catch (e) { ctx = null; }
  if (!ctx) { finish(false); return; }
  cv.className = "intro-canvas"; cv.setAttribute("aria-hidden", "true");
  document.body.appendChild(cv);
  var dpr = Math.min(2, window.devicePixelRatio || 1), vw = 0, vh = 0;
  function resize() { vw = window.innerWidth; vh = window.innerHeight; cv.width = Math.round(vw * dpr); cv.height = Math.round(vh * dpr); }
  resize(); window.addEventListener("resize", resize);

  /* colours from the stylesheet, so the mark is right in either theme */
  var C = {}, tints = {};
  function parseColor(s) {
    s = (s || "").trim();
    var m = /^#([0-9a-f]{3,8})$/i.exec(s);
    if (m) { var h = m[1]; if (h.length < 6) h = h.split("").map(function (c) { return c + c; }).join(""); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; }
    m = /^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i.exec(s);
    return m ? [+m[1], +m[2], +m[3]] : null;
  }
  (function () {
    var cs = getComputedStyle(html), v = function (n, fb) { return parseColor(cs.getPropertyValue(n)) || fb; };
    C.ink = v("--ink", [17, 24, 39]); C.accent = v("--accent", [37, 99, 235]); C.signal = v("--signal", [217, 119, 6]); C.paper = v("--paper", [255, 255, 255]);
    C.dark = (0.2126 * C.paper[0] + 0.7152 * C.paper[1] + 0.0722 * C.paper[2]) / 255 < 0.5;
  })();
  function rgba(c, a) { return "rgba(" + (c[0] | 0) + "," + (c[1] | 0) + "," + (c[2] | 0) + "," + Math.max(0, Math.min(1, a)).toFixed(3) + ")"; }
  function mix(a, b, t) { var q = function (v) { return Math.round(v / 6) * 6; }; return [q(a[0] + (b[0] - a[0]) * t), q(a[1] + (b[1] - a[1]) * t), q(a[2] + (b[2] - a[2]) * t)]; }
  var sprite = document.createElement("canvas"); sprite.width = sprite.height = 64;
  (function () {
    var c = sprite.getContext("2d"), g = c.createRadialGradient(32, 32, 0, 32, 32, 32);
    g.addColorStop(0, "rgba(255,255,255,1)"); g.addColorStop(0.2, "rgba(255,255,255,0.7)"); g.addColorStop(0.5, "rgba(255,255,255,0.18)"); g.addColorStop(1, "rgba(255,255,255,0)");
    c.fillStyle = g; c.fillRect(0, 0, 64, 64);
  })();
  function tinted(c) {
    var key = (c[0] | 0) + "," + (c[1] | 0) + "," + (c[2] | 0);
    if (tints[key]) return tints[key];
    var t = document.createElement("canvas"); t.width = t.height = 64; var x = t.getContext("2d");
    x.drawImage(sprite, 0, 0); x.globalCompositeOperation = "source-in"; x.fillStyle = "rgb(" + key + ")"; x.fillRect(0, 0, 64, 64);
    return (tints[key] = t);
  }
  function blob(c, x, y, r, a) { if (a <= 0.004 || r <= 0.3) return; ctx.globalAlpha = Math.min(1, a); ctx.drawImage(tinted(c), x - r, y - r, r * 2, r * 2); }
  function dot(c, x, y, r, a) { if (a <= 0.004 || r <= 0.2) return; ctx.globalAlpha = Math.min(1, a); ctx.fillStyle = rgba(c, 1); ctx.beginPath(); ctx.arc(x, y, r, 0, 6.2832); ctx.fill(); }
  function line(a, b, c, w, alpha) { if (alpha <= 0.004) return; ctx.globalAlpha = alpha; ctx.strokeStyle = rgba(c, 1); ctx.lineWidth = w; ctx.lineCap = "round"; ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.stroke(); }

  var clamp01 = function (t) { return t < 0 ? 0 : t > 1 ? 1 : t; };
  var easeInOut = function (t) { return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
  var easeOutC = function (t) { return 1 - Math.pow(1 - t, 3); };
  function lerp(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t]; }
  function along(s, p) { return lerp(s.a, s.b, p); }

  /* ── the mark: a severed wire, alone, mid-page ─────────────── */
  var mark = (function () {
    var W = Math.min(vw * 0.72, 880), gap = Math.max(96, W * 0.24), cx = vw / 2, y = vh * 0.46;
    return { in: { a: [cx - W / 2, y], b: [cx - gap / 2, y] }, out: { a: [cx + gap / 2, y], b: [cx + W / 2, y] } };
  })();
  var shape = { in: { a: mark.in.a.slice(), b: mark.in.b.slice() }, out: { a: mark.out.a.slice(), b: mark.out.b.slice() } };
  var cloud = [];
  [mark.in, mark.out].forEach(function (s, k) {
    var len = Math.hypot(s.b[0] - s.a[0], s.b[1] - s.a[1]), n = Math.round(Math.min(130, Math.max(30, len / 5)));
    for (var i = 0; i < n; i++) {
      var u = Math.random(), p = along(s, u), off = (Math.random() - 0.5) * 2 * (14 + Math.random() * 34), slide = (Math.random() - 0.5) * 40;
      cloud.push({ seg: k, u: u, x: p[0], y: p[1], sx: p[0] + slide, sy: p[1] + off, r: 0.7 + Math.random() * 1.3, tw: Math.random() * 6.283 });
    }
  });
  var sparks = [], blooms = [], trail = [];
  function spark(x, y, vx, vy, life, r, c) { sparks.push({ x: x, y: y, vx: vx, vy: vy, life: life, age: 0, r: r, c: c }); }
  function burst(p, c, n, speed) { for (var i = 0; i < n; i++) { var a = Math.random() * 6.283, v = speed * (0.35 + Math.random() * 0.65); spark(p[0], p[1], Math.cos(a) * v, Math.sin(a) * v * 0.85, 560 + Math.random() * 520, 0.8 + Math.random() * 1.3, c); } }

  /* ── timing (ms from the first frame) ──────────────────────── */
  var T = { draw0: 140, draw1: 1060, land: 1060, lift: 1280, fly1: 1900, end: 1820 };
  var start = 0, raf = 0, last = 0, landed = false, flying = false, target = null, fadeOut = 0;

  function frame(now) {
    raf = requestAnimationFrame(frame);
    if (!start) { start = now; last = now; }
    var dt = Math.min(48, now - last); last = now; var k = dt / 16.667, t = now - start;
    var glowOp = C.dark ? "lighter" : "source-over", lum = C.dark ? 1.25 : 1;

    /* choreography */
    var pIn = easeInOut(clamp01((t - T.draw0) / (T.draw1 - T.draw0)));
    var pOut = easeInOut(clamp01((t - (T.draw0 + 330)) / (T.draw1 - T.draw0 - 330)));
    if (!landed && t >= T.land) {
      landed = true; cloud = [];
      blooms.push({ x: mark.in.b[0], y: mark.in.b[1], c: C.signal, age: 0, dur: 900, r1: 150, ring: 100 });
      burst(mark.in.b, C.signal, 28, 3.2);
    }
    if (!done && !lifted && t >= T.lift) {
      /* the page lifts; on the home page the mark flies into the hero wire */
      target = (window.aitmWireTarget && window.aitmWireTarget()) || null;
      if (target) { flying = true; detail.morphed = true; }
      reveal(false);
    }
    if (!done && t >= (flying ? T.fly1 : T.end)) finish(false);
    var fly = flying ? easeInOut(clamp01((t - T.lift) / (T.fly1 - T.lift))) : 0;
    if (flying && target) {
      shape.in.a = lerp(mark.in.a, target.in.a, fly); shape.in.b = lerp(mark.in.b, target.in.b, fly);
      shape.out.a = lerp(mark.out.a, target.out.a, fly); shape.out.b = lerp(mark.out.b, target.out.b, fly);
    }
    /* the mark's own brightness: it fades with the lift when it has nowhere to fly,
       and fades out quickly once it has handed over (or been skipped) */
    var alpha = 1;
    if (fadeOut) alpha = 1 - clamp01((now - fadeOut) / 380);
    else if (lifted && !flying) alpha = 1 - clamp01((t - T.lift) / (T.end - T.lift));

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, vw, vh);
    if (alpha <= 0.004) return;

    /* the gather */
    if (cloud.length) {
      var appear = clamp01((t - 40) / 300);
      for (var i = 0; i < cloud.length; i++) {
        var q = cloud[i], lead = q.seg === 0 ? pIn - q.u : pOut - (1 - q.u);
        var f = easeOutC(clamp01((lead + 0.3) / 0.3)), fade = 1 - clamp01(lead / 0.09);
        if (fade <= 0) continue;
        var x = q.sx + (q.x - q.sx) * f, y = q.sy + (q.y - q.sy) * f;
        var a = appear * fade * (0.3 + 0.5 * f) * (0.8 + 0.2 * Math.sin(now / 380 + q.tw)) * alpha;
        dot(C.ink, x, y, q.r * (0.8 + 0.4 * f), a * 0.85);
        ctx.globalCompositeOperation = glowOp; blob(C.accent, x, y, q.r * 4.5, a * 0.22 * lum); ctx.globalCompositeOperation = "source-over";
      }
    }

    /* the wire, as far as it is drawn */
    if (pIn > 0) line(shape.in.a, along(shape.in, pIn), C.ink, 2, alpha);
    if (pOut > 0) line(along(shape.out, 1 - pOut), shape.out.b, C.ink, 2, alpha);

    /* the comet's head and the wire lit behind it */
    var head = pIn > 0 ? along(shape.in, pIn) : null, hc = landed ? mix(C.accent, C.signal, clamp01((t - T.land) / 360)) : C.accent;
    var moving = pIn > 0 && pIn < 1;
    if (head) {
      ctx.globalCompositeOperation = glowOp;
      var tail = along(shape.in, Math.max(0, pIn - 0.45)), la = alpha * (landed ? 1 - clamp01((t - T.land) / 900) : 1);
      if (la > 0.004 && pIn > 0.002) {
        var g = ctx.createLinearGradient(tail[0], tail[1], head[0], head[1]); g.addColorStop(0, rgba(C.accent, 0)); g.addColorStop(1, rgba(C.accent, 0.9));
        ctx.strokeStyle = g; ctx.lineCap = "round"; ctx.lineWidth = 10; ctx.globalAlpha = 0.14 * la; ctx.beginPath(); ctx.moveTo(tail[0], tail[1]); ctx.lineTo(head[0], head[1]); ctx.stroke();
        ctx.lineWidth = 2.5; ctx.globalAlpha = la; ctx.beginPath(); ctx.moveTo(tail[0], tail[1]); ctx.lineTo(head[0], head[1]); ctx.stroke();
      }
      var lastT = trail.length ? trail[trail.length - 1] : null;
      if (moving && (!lastT || Math.hypot(head[0] - lastT.x, head[1] - lastT.y) >= 2.5)) { trail.push({ x: head[0], y: head[1] }); if (trail.length > 30) trail.shift(); }
      else if (trail.length && !moving) trail.splice(0, 2);
      for (var tt = 0; tt < trail.length; tt++) { var w = (tt + 1) / (trail.length + 1); blob(C.accent, trail[tt].x, trail[tt].y, 3 + 12 * w, alpha * 0.34 * w * w * lum); }
      if (moving && Math.random() < 0.7) { var side = (Math.random() - 0.5) * 1.2, back = -(0.3 + Math.random() * 0.6); spark(head[0], head[1], back, side, 280 + Math.random() * 380, 0.6 + Math.random() * 0.9, C.accent); }
    }
    /* the far side's drawing tip */
    if (pOut > 0 && pOut < 1) {
      var tip = along(shape.out, 1 - pOut), ta = clamp01(pOut / 0.1) * (1 - clamp01((pOut - 0.88) / 0.12)) * alpha;
      ctx.globalCompositeOperation = glowOp; blob(C.ink, tip[0], tip[1], 10, 0.45 * ta * lum); ctx.globalCompositeOperation = "source-over"; dot(C.ink, tip[0], tip[1], 2.2, ta);
    }
    /* blooms and sparks */
    ctx.globalCompositeOperation = glowOp;
    for (var b = blooms.length - 1; b >= 0; b--) {
      var B = blooms[b]; B.age += dt; var e = clamp01(B.age / B.dur), re = easeOutC(e);
      if (e >= 1) { blooms.splice(b, 1); continue; }
      /* the bloom stays with the cut as the mark flies */
      var bx = shape.in.b[0], by = shape.in.b[1];
      blob(B.c, bx, by, 14 + B.r1 * re, (C.dark ? 0.6 : 0.42) * Math.pow(1 - e, 1.4) * lum * alpha);
      ctx.globalAlpha = 0.65 * Math.pow(1 - e, 1.2) * alpha; ctx.strokeStyle = rgba(B.c, 1); ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(bx, by, 4 + B.ring * re, 0, 6.2832); ctx.stroke();
    }
    for (var s = sparks.length - 1; s >= 0; s--) {
      var S = sparks[s]; S.age += dt; if (S.age >= S.life) { sparks.splice(s, 1); continue; }
      S.x += S.vx * k; S.y += S.vy * k; var drag = Math.pow(0.955, k); S.vx *= drag; S.vy *= drag;
      var sa = Math.pow(1 - S.age / S.life, 1.6) * alpha; blob(S.c, S.x, S.y, S.r * 4, sa * 0.5 * lum); dot(S.c, S.x, S.y, S.r, sa * 0.95);
    }
    if (head) {
      var breathe = moving ? 1 : 1 + 0.14 * Math.sin(now / 430);
      blob(hc, head[0], head[1], 20 * breathe, 0.62 * alpha * lum);
      if (landed) blob(C.signal, head[0], head[1], 38 * breathe, 0.2 * alpha * lum);
      ctx.globalCompositeOperation = "source-over";
      dot(C.ink, head[0], head[1], 4.6, alpha);
      if (C.dark) dot([255, 255, 255], head[0], head[1], 2, 0.85 * alpha);
    }
    ctx.globalAlpha = 1; ctx.globalCompositeOperation = "source-over";
  }
  raf = requestAnimationFrame(frame);
})();
