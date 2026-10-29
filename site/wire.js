/* aitmproxy — the wire. The hero's live scene and its light.

   The DOM is the scene: wire.js flips data-phase on .wire and data-state on .held, and
   styles.css does every transition (the arm ticks, the badge, the edit, the labels).
   Over it sits one Canvas2D layer that draws nothing but light: on the first run the
   wire gathers from particles and draws itself with a comet at its tip, the comet lands
   in the cut and ignites the held flow with an amber bloom, and from then on the comet
   is the packet in every loop — a glowing head, a trailing tail, the wire lit behind it,
   a green settle when the edited request lands 200.

   It pauses off screen and in background tabs, follows the system theme by reading the
   site's own CSS variables, and under reduced motion (or without a canvas) steps aside:
   the scene rests at its end state or runs on the CSS packets alone. Decorative only —
   the canvas is aria-hidden and nothing readable depends on it. */
(function () {
  "use strict";

  var wire = document.querySelector(".hero .wire");
  if (!wire) return;
  var held = wire.querySelector(".held"), badge = wire.querySelector(".held .state");
  var segIn = wire.querySelector(".wire-seg--in"), segOut = wire.querySelector(".wire-seg--out");
  if (!held || !badge || !segIn || !segOut) return;

  var mm = function (q) { return window.matchMedia ? window.matchMedia(q) : null; };
  var mqReduce = mm("(prefers-reduced-motion: reduce)"), mqDark = mm("(prefers-color-scheme: dark)");

  /* ── the DOM side of the scene ─────────────────────────────── */
  function setPhase(p) { wire.setAttribute("data-phase", p); }
  function setHeld(state, word) {
    held.setAttribute("data-state", state);
    if (badge.textContent !== word) {
      badge.textContent = word;
      badge.removeAttribute("data-cue"); void badge.offsetWidth; badge.setAttribute("data-cue", "swap");
    }
  }
  /* the end state: a request held in the gap, armed */
  function rest() {
    segIn.style.transform = ""; segOut.style.transform = "";
    setPhase("held"); setHeld("armed", "armed");
  }
  if (mqReduce && mqReduce.matches) { rest(); return; }

  /* ── timeline ──────────────────────────────────────────────── */
  var PH = { intro: 1750, arrive: 1150, held: 2600, resume: 1050, done: 1900, idle: 450 };
  var NEXT = { intro: "held", arrive: "held", held: "resume", resume: "done", done: "idle", idle: "arrive" };
  var phase = null, t0 = 0, dur = 0, editCued = false;

  /* ── the canvas ────────────────────────────────────────────── */
  var cv = document.createElement("canvas"), ctx = null;
  try { ctx = cv.getContext("2d"); } catch (e) { ctx = null; }
  if (ctx) {
    cv.className = "wire-canvas"; cv.setAttribute("aria-hidden", "true");
    wire.insertBefore(cv, wire.firstChild);
    wire.setAttribute("data-canvas", "");
  }
  var dpr = 1, cw = 0, ch = 0, G = null;

  /* colours come from the stylesheet, so light and dark both hold */
  var C = {}, tints = {};
  function parseColor(s) {
    s = (s || "").trim();
    var m = /^#([0-9a-f]{3,8})$/i.exec(s);
    if (m) {
      var h = m[1];
      if (h.length < 6) h = h.split("").map(function (c) { return c + c; }).join("");
      return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
    }
    m = /^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i.exec(s);
    return m ? [+m[1], +m[2], +m[3]] : null;
  }
  function readColors() {
    var cs = getComputedStyle(wire);
    var v = function (name, fb) { return parseColor(cs.getPropertyValue(name)) || fb; };
    C.ink = v("--ink", [17, 24, 39]); C.accent = v("--accent", [37, 99, 235]);
    C.signal = v("--signal", [217, 119, 6]); C.ok = v("--st-ok", [21, 128, 61]);
    C.paper = v("--paper", [255, 255, 255]);
    var L = (0.2126 * C.paper[0] + 0.7152 * C.paper[1] + 0.0722 * C.paper[2]) / 255;
    C.dark = L < 0.5;
    tints = {};
  }
  function rgba(c, a) { return "rgba(" + (c[0] | 0) + "," + (c[1] | 0) + "," + (c[2] | 0) + "," + Math.max(0, Math.min(1, a)).toFixed(3) + ")"; }
  function mix(a, b, t) { var q = function (v) { return Math.round(v / 6) * 6; }; return [q(a[0] + (b[0] - a[0]) * t), q(a[1] + (b[1] - a[1]) * t), q(a[2] + (b[2] - a[2]) * t)]; }

  /* a soft light sprite, tinted per colour and drawn scaled: every glow is one of these */
  var sprite = document.createElement("canvas"); sprite.width = sprite.height = 64;
  (function () {
    var c = sprite.getContext("2d"); if (!c) return;
    var g = c.createRadialGradient(32, 32, 0, 32, 32, 32);
    g.addColorStop(0, "rgba(255,255,255,1)"); g.addColorStop(0.2, "rgba(255,255,255,0.7)");
    g.addColorStop(0.5, "rgba(255,255,255,0.18)"); g.addColorStop(1, "rgba(255,255,255,0)");
    c.fillStyle = g; c.fillRect(0, 0, 64, 64);
  })();
  function tinted(c) {
    var key = (c[0] | 0) + "," + (c[1] | 0) + "," + (c[2] | 0);
    if (tints[key]) return tints[key];
    var t = document.createElement("canvas"); t.width = t.height = 64;
    var x = t.getContext("2d");
    x.drawImage(sprite, 0, 0); x.globalCompositeOperation = "source-in"; x.fillStyle = "rgb(" + key + ")"; x.fillRect(0, 0, 64, 64);
    return (tints[key] = t);
  }
  function blob(c, x, y, r, a) { if (a <= 0.004 || r <= 0.3) return; ctx.globalAlpha = Math.min(1, a); ctx.drawImage(tinted(c), x - r, y - r, r * 2, r * 2); }
  function dot(c, x, y, r, a) { if (a <= 0.004 || r <= 0.2) return; ctx.globalAlpha = Math.min(1, a); ctx.fillStyle = rgba(c, 1); ctx.beginPath(); ctx.arc(x, y, r, 0, 6.2832); ctx.fill(); }

  /* ── geometry, in canvas pixels: the two segments of the wire ── */
  function resize() {
    if (!ctx) return;
    var r = cv.getBoundingClientRect(); cw = r.width; ch = r.height;
    dpr = Math.min(2, window.devicePixelRatio || 1);
    cv.width = Math.round(cw * dpr); cv.height = Math.round(ch * dpr);
  }
  function measure() {
    if (!ctx) return;
    var saved = [segIn.style.transform, segOut.style.transform];
    segIn.style.transform = "none"; segOut.style.transform = "none";
    var r = cv.getBoundingClientRect();
    var seg = function (el) {
      var b = el.getBoundingClientRect(), vert = b.height > b.width;
      var a = vert ? [b.left + b.width / 2, b.top] : [b.left, b.top + b.height / 2];
      var z = vert ? [b.left + b.width / 2, b.bottom] : [b.right, b.top + b.height / 2];
      a = [a[0] - r.left, a[1] - r.top]; z = [z[0] - r.left, z[1] - r.top];
      return { a: a, b: z, vert: vert, len: Math.hypot(z[0] - a[0], z[1] - a[1]) || 1 };
    };
    G = { in: seg(segIn), out: seg(segOut) };
    segIn.style.transform = saved[0]; segOut.style.transform = saved[1];
  }
  function along(s, p) { return [s.a[0] + (s.b[0] - s.a[0]) * p, s.a[1] + (s.b[1] - s.a[1]) * p]; }
  function scaleSeg(el, s, p) { el.style.transform = (s && s.vert ? "scaleY(" : "scaleX(") + p.toFixed(4) + ")"; }

  var clamp01 = function (t) { return t < 0 ? 0 : t > 1 ? 1 : t; };
  var easeInOut = function (t) { return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
  var easeOutQ = function (t) { return 1 - Math.pow(1 - t, 4); };
  var easeOutC = function (t) { return 1 - Math.pow(1 - t, 3); };

  /* ── the material: cloud, comet, trail, sparks, blooms ─────── */
  var cloud = [], trail = [], sparks = [], blooms = [], head = null, lastHead = null;

  /* the wire's particles: scattered about each segment, they gather onto it ahead of the drawing tip */
  function seedCloud() {
    cloud = [];
    if (!G) return;
    [G.in, G.out].forEach(function (s, k) {
      var n = Math.round(Math.min(70, Math.max(18, s.len / 12)));
      for (var i = 0; i < n; i++) {
        var u = Math.random(), p = along(s, u);
        var off = (Math.random() - 0.5) * 2 * (8 + Math.random() * 18), slide = (Math.random() - 0.5) * 24;
        var sx = s.vert ? p[0] + off : p[0] + slide, sy = s.vert ? p[1] + slide : p[1] + off;
        cloud.push({ seg: k, u: u, x: p[0], y: p[1], sx: sx, sy: sy, r: 0.6 + Math.random() * 1.1, tw: Math.random() * 6.283 });
      }
    });
  }
  function spark(x, y, vx, vy, life, r, c, glow) { sparks.push({ x: x, y: y, vx: vx, vy: vy, life: life, age: 0, r: r, c: c, glow: glow }); if (sparks.length > 90) sparks.shift(); }
  function burst(p, c, n, speed) {
    for (var i = 0; i < n; i++) {
      var a = Math.random() * 6.283, v = speed * (0.35 + Math.random() * 0.65);
      spark(p[0], p[1], Math.cos(a) * v, Math.sin(a) * v * 0.85, 520 + Math.random() * 480, 0.8 + Math.random() * 1.1, c, true);
    }
  }
  function bloom(p, c, scale) { blooms.push({ x: p[0], y: p[1], c: c, age: 0, dur: 820, r1: 120 * scale, ring: 80 * scale }); }

  /* ── choreography: what each phase means for the DOM and the light ── */
  function enter(p, now) {
    var from = phase;
    phase = p; dur = PH[p]; t0 = now;
    switch (p) {
      case "intro":
        setPhase("intro"); setHeld("", "—");
        measure(); seedCloud();
        if (G) { scaleSeg(segIn, G.in, 0); scaleSeg(segOut, G.out, 0); }
        break;
      case "arrive":
        setPhase("arrive"); setHeld("", "—"); measure();
        break;
      case "held":
        segIn.style.transform = ""; segOut.style.transform = ""; cloud = [];
        setPhase("held"); setHeld("armed", "armed");
        held.removeAttribute("data-cue"); editCued = false;
        /* the first landing ignites the scene; every later one is a quieter arming */
        if (G) { var big = from === "intro"; bloom(G.in.b, C.signal, big ? 1 : 0.62); burst(G.in.b, C.signal, big ? 24 : 12, big ? 2.8 : 1.9); }
        break;
      case "resume":
        setPhase("resume"); setHeld("resuming", "resuming…");
        break;
      case "done":
        setPhase("done"); setHeld("done", "200");
        if (G) { bloom(G.out.b, C.ok, 0.55); burst(G.out.b, C.ok, 10, 1.6); }
        break;
      case "idle":
        setPhase("idle"); setHeld("", "—");
        break;
    }
  }

  /* per frame: the DOM pieces the CSS cannot time on its own */
  function update(now, u) {
    if (phase === "intro" && G) {
      var pIn = easeInOut(clamp01((u - 0.31) / 0.69)), pOut = easeInOut(clamp01((u - 0.54) / 0.46));
      scaleSeg(segIn, G.in, pIn); scaleSeg(segOut, G.out, pOut);
    }
    if (phase === "held" && u > 0.3 && !editCued) { editCued = true; held.setAttribute("data-cue", "edit"); }
  }

  /* where the comet is, what colour it burns, how bright */
  function comet(now, u) {
    if (!G) return null;
    var ms = u * dur, h = null;
    if (phase === "intro") {
      var p = easeInOut(clamp01((u - 0.31) / 0.69));
      if (p <= 0) return null;
      h = { pos: along(G.in, p), seg: G.in, p: p, c: C.accent, a: clamp01(p / 0.06), moving: true };
    } else if (phase === "arrive") {
      var q = easeOutQ(u);
      h = { pos: along(G.in, q), seg: G.in, p: q, c: C.accent, a: clamp01(ms / 140), moving: true };
    } else if (phase === "held") {
      h = { pos: G.in.b, seg: G.in, p: 1, c: mix(C.accent, C.signal, clamp01(ms / 360)), a: 1, moving: false, cool: clamp01(ms / 900) };
    } else if (phase === "resume") {
      var r = easeOutQ(u);
      h = { pos: along(G.out, r), seg: G.out, p: r, c: mix(C.signal, C.accent, clamp01(u / 0.3)), a: 1, moving: true };
    } else if (phase === "done") {
      h = { pos: G.out.b, seg: G.out, p: 1, c: mix(C.accent, C.ok, clamp01(ms / 300)), a: 1 - clamp01((ms - 180) / 520), moving: false, cool: clamp01(ms / 700) };
    }
    return h;
  }

  function litWire(s, p, c, alpha) {
    if (p <= 0.002 || alpha <= 0.004) return;
    var h = along(s, p), t = along(s, Math.max(0, p - 0.45));
    var g = ctx.createLinearGradient(t[0], t[1], h[0], h[1]);
    g.addColorStop(0, rgba(c, 0)); g.addColorStop(1, rgba(c, 0.9));
    ctx.strokeStyle = g; ctx.lineCap = "round";
    ctx.lineWidth = 10; ctx.globalAlpha = 0.14 * alpha;
    ctx.beginPath(); ctx.moveTo(t[0], t[1]); ctx.lineTo(h[0], h[1]); ctx.stroke();
    ctx.lineWidth = 2.5; ctx.globalAlpha = alpha;
    ctx.beginPath(); ctx.moveTo(t[0], t[1]); ctx.lineTo(h[0], h[1]); ctx.stroke();
  }

  function draw(now, u, dt) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cw, ch);
    ctx.globalCompositeOperation = "source-over";
    var glowOp = C.dark ? "lighter" : "source-over", lum = C.dark ? 1.25 : 1;
    var k = dt / 16.667;

    /* the gather: the wire forms from its particles just ahead of the drawing tip */
    if (phase === "intro" && cloud.length) {
      var pIn = easeInOut(clamp01((u - 0.31) / 0.69)), pOut = easeInOut(clamp01((u - 0.54) / 0.46));
      var appear = clamp01((u - 0.06) / 0.22);
      for (var i = 0; i < cloud.length; i++) {
        var q = cloud[i], lead = q.seg === 0 ? pIn - q.u : pOut - (1 - q.u);
        var f = easeOutC(clamp01((lead + 0.28) / 0.28)), fade = 1 - clamp01(lead / 0.09);
        if (fade <= 0) continue;
        var x = q.sx + (q.x - q.sx) * f, y = q.sy + (q.y - q.sy) * f;
        var a = appear * fade * (0.28 + 0.5 * f) * (0.8 + 0.2 * Math.sin(now / 380 + q.tw));
        dot(C.ink, x, y, q.r * (0.8 + 0.4 * f), a * 0.85);
        ctx.globalCompositeOperation = glowOp; blob(C.accent, x, y, q.r * 4, a * 0.22 * lum); ctx.globalCompositeOperation = "source-over";
      }
      /* the far side draws itself from the server toward the cut, with a small spark at its tip */
      if (pOut > 0 && pOut < 1 && G) {
        var tip = along(G.out, 1 - pOut), ta = clamp01(pOut / 0.1) * (1 - clamp01((pOut - 0.88) / 0.12));
        ctx.globalCompositeOperation = glowOp; blob(C.ink, tip[0], tip[1], 9, 0.45 * ta * lum); ctx.globalCompositeOperation = "source-over";
        dot(C.ink, tip[0], tip[1], 2.2, ta);
      }
    }

    head = comet(now, u);

    /* the wire lit behind the comet; it cools once the comet has stopped */
    if (head) {
      var la = head.a * (head.moving ? 1 : 1 - (head.cool || 0));
      ctx.globalCompositeOperation = glowOp; litWire(head.seg, head.p, head.c, la * 0.9);
      ctx.globalCompositeOperation = "source-over";
    }

    /* blooms: the ignition at the cut, the settle at the server */
    ctx.globalCompositeOperation = glowOp;
    for (var b = blooms.length - 1; b >= 0; b--) {
      var B = blooms[b]; B.age += dt; var e = clamp01(B.age / B.dur), re = easeOutC(e);
      if (e >= 1) { blooms.splice(b, 1); continue; }
      blob(B.c, B.x, B.y, 12 + B.r1 * re, (C.dark ? 0.6 : 0.4) * Math.pow(1 - e, 1.4) * lum);
      ctx.globalAlpha = 0.65 * Math.pow(1 - e, 1.2); ctx.strokeStyle = rgba(B.c, 1); ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(B.x, B.y, 4 + B.ring * re, 0, 6.2832); ctx.stroke();
    }

    /* the tail: the comet's recent positions, fainter and smaller the older they are.
       Points are kept a step apart, so a slowing comet's tail shortens into its head
       rather than piling up; once it stops, the tail drains into it. */
    var lastT = trail.length ? trail[trail.length - 1] : null;
    if (head && head.moving && (!lastT || Math.hypot(head.pos[0] - lastT.x, head.pos[1] - lastT.y) >= 2.5)) {
      trail.push({ x: head.pos[0], y: head.pos[1], c: head.c, a: head.a });
      if (trail.length > 28) trail.shift();
    } else if (trail.length && (!head || !head.moving)) { trail.splice(0, 2); }
    var n = trail.length;
    for (var t = 0; t < n; t++) {
      var T = trail[t], w = (t + 1) / (n + 1);
      blob(T.c, T.x, T.y, 3 + 10 * w, T.a * 0.34 * w * w * lum);
    }

    /* sparks shed while moving, thrown on ignition */
    if (head && head.moving && lastHead && Math.hypot(head.pos[0] - lastHead[0], head.pos[1] - lastHead[1]) > 0.8 && Math.random() < 0.7) {
      var dx = head.pos[0] - lastHead[0], dy = head.pos[1] - lastHead[1], L = Math.hypot(dx, dy) || 1; dx /= L; dy /= L;
      var side = (Math.random() - 0.5) * 1.1, back = -(0.25 + Math.random() * 0.55);
      spark(head.pos[0], head.pos[1], dx * back - dy * side, dy * back + dx * side, 260 + Math.random() * 360, 0.6 + Math.random() * 0.9, head.c, false);
    }
    for (var s = sparks.length - 1; s >= 0; s--) {
      var S = sparks[s]; S.age += dt;
      if (S.age >= S.life) { sparks.splice(s, 1); continue; }
      S.x += S.vx * k; S.y += S.vy * k; var drag = Math.pow(0.955, k); S.vx *= drag; S.vy *= drag;
      var sa = Math.pow(1 - S.age / S.life, 1.6);
      if (S.glow) blob(S.c, S.x, S.y, S.r * 4, sa * 0.5 * lum);
      dot(S.c, S.x, S.y, S.r, sa * 0.95);
    }

    /* the head: a soft glow in the state's colour, a bright core, and the breath it holds in the gap */
    if (head) {
      var breathe = head.moving ? 1 : 1 + 0.14 * Math.sin(now / 430);
      blob(head.c, head.pos[0], head.pos[1], 18 * breathe, 0.62 * head.a * lum);
      if (!head.moving && phase === "held") { var tight = head.seg.vert; blob(C.signal, head.pos[0], head.pos[1], (tight ? 22 : 34) * breathe, (tight ? 0.14 : 0.2) * head.a * lum); }
      ctx.globalCompositeOperation = "source-over";
      dot(C.ink, head.pos[0], head.pos[1], 4.6, head.a);
      if (C.dark) dot([255, 255, 255], head.pos[0], head.pos[1], 2, 0.85 * head.a);
      lastHead = head.pos;
    } else lastHead = null;
    ctx.globalAlpha = 1; ctx.globalCompositeOperation = "source-over";
  }

  /* ── the clock: pausable, kept on the beat ──────────────────── */
  var raf = 0, last = 0, pausedAt = 0, started = false, dead = false, visible = !document.hidden, onScreen = true;
  function frame(now) {
    raf = requestAnimationFrame(frame);
    var dt = last ? Math.min(48, now - last) : 16; last = now;
    var guard = 0;
    while (now - t0 >= dur && guard++ < 8) { var over = now - t0 - dur; enter(NEXT[phase], now - Math.min(over, 120)); }
    var u = clamp01((now - t0) / dur);
    update(now, u);
    if (ctx) draw(now, u, dt);
  }
  function run() { if (raf || !started || dead) return; var now = performance.now(); if (pausedAt) { t0 += now - pausedAt; pausedAt = 0; } last = 0; raf = requestAnimationFrame(frame); }
  function halt() { if (!raf) return; cancelAnimationFrame(raf); raf = 0; pausedAt = performance.now(); }
  function sync() { if (visible && onScreen) run(); else halt(); }
  document.addEventListener("visibilitychange", function () { visible = !document.hidden; sync(); });

  /* the first run gets the introduction only if the wire is on screen now; otherwise a
     request simply arrives when the hero is scrolled into view */
  var r0 = wire.getBoundingClientRect(), vh = window.innerHeight || document.documentElement.clientHeight || 800;
  var withIntro = !!ctx && r0.top < vh && r0.bottom > 0;
  setPhase(withIntro ? "intro" : "idle"); /* synchronously: the stylesheet's wait ends here */
  function begin() {
    if (started || dead) return; started = true;
    readColors(); resize(); measure();
    enter(withIntro ? "intro" : "arrive", performance.now());
    sync(); /* runs only if on screen and visible; otherwise waits, on the beat, for the observer */
    /* if frames never come (a throttled renderer), the introduction must not keep the flow
       hidden: land it in the held state by timer, and the loop carries on from there */
    if (withIntro) setTimeout(function () { if (phase === "intro") enter("held", performance.now()); }, PH.intro + 2500);
  }
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (es) {
      es.forEach(function (e) { onScreen = e.isIntersecting; if (onScreen && !started) begin(); else sync(); });
    }, { threshold: 0.15 }).observe(wire);
    setTimeout(function () { if (!started) begin(); }, 2500); /* never leave the introduction waiting */
  } else begin();

  /* the layout moves (fonts land, the window resizes): keep the light on the wire */
  if ("ResizeObserver" in window) {
    var ro = new ResizeObserver(function () { resize(); measure(); });
    ro.observe(wire); ro.observe(segIn); ro.observe(segOut);
  } else window.addEventListener("resize", function () { resize(); measure(); });

  /* the theme or the motion preference can change under us */
  if (mqDark && mqDark.addEventListener) mqDark.addEventListener("change", readColors);
  if (mqReduce && mqReduce.addEventListener) mqReduce.addEventListener("change", function (e) {
    if (!e.matches) return;
    halt(); dead = true; started = true;
    if (ctx && cv.parentNode) cv.parentNode.removeChild(cv);
    wire.removeAttribute("data-canvas"); rest();
  });
})();
