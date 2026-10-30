/* aitmproxy — the hero "weave".

   The DOM is the scene: this draws nothing readable. A flow-viewer panel sits on the wire
   as the interceptor; behind it a field of plasma strands carries other traffic we are not
   touching. One request travels in on the wire (accent), and on arrival it is BUILT inside
   the panel row by row — not exploded, written into being — held and edited (armed, amber),
   then released on the far side in its changed colour (signal → ok) back onto the wire to
   the server, which lands 200. The plasma keeps flowing throughout.

   It pauses off screen and in background tabs, follows the system theme by reading the
   site's own CSS variables, and under reduced motion steps aside: the panel rests built and
   armed on the CSS alone. Decorative only — the canvas is aria-hidden and nothing readable
   depends on it. On the home page it takes over from the site introduction (intro.js): the
   mark flies into this wire and the request builds where it lands. */
(function () {
  "use strict";

  var host = document.querySelector(".hero .weave"); if (!host) return;
  var panel = host.querySelector(".weave-panel");
  var badge = panel && panel.querySelector(".state");
  var legend = Array.prototype.slice.call(host.querySelectorAll(".proto-legend li"));
  var html = document.documentElement;
  var mm = function (q) { return window.matchMedia ? window.matchMedia(q) : null; };
  var mqReduce = mm("(prefers-reduced-motion: reduce)"), mqDark = mm("(prefers-color-scheme: dark)");

  /* the four message types on the wire. Each cycle of the loop builds, holds and
     releases one of them, so a viewer sees the breadth: an HTTP request, a WebSocket
     frame, an HTTP/2 frame, a raw L4 packet — each with its own badge and its own
     representative on-the-wire shape. The incoming packet and the panel chip take the
     protocol's hue; "held" is always amber and "200" is always green, whatever the type. */
  var PROTOCOLS = [
    { key: "http", proto: "HTTP/1.1", id: "#41", m: "POST", mc: "m-post", path: "/api/cart/items", edit: "99", rows: [
      '<span class="h">host:</span> shop.example.com',
      '<span class="h">content-type:</span> application/json',
      '<span class="h">authorization:</span> Bearer eyJhbGciOiJIUzI1NiJ9…',
      '&nbsp;',
      '{ "sku": "A-1042", "qty": <span class="edit">999</span> }'
    ] },
    { key: "ws", proto: "WebSocket", id: "#43", m: "WS", mc: "m-ws", path: "wss://api.example.com/live", rows: [
      '<span class="dir">↓</span> <span class="h">text</span> {"op":"welcome","id":"c-7f2"}',
      '<span class="dir">↑</span> <span class="h">text</span> {"op":"subscribe","ch":"orders"}',
      '<span class="dir">↑</span> <span class="h">injected</span> {"op":"subscribe","ch":<span class="edit">"admin"</span>}',
      '<span class="dir">↓</span> <span class="h">text</span> {"op":"ack","ch":"admin"}'
    ] },
    { key: "h2", proto: "HTTP/2", id: "#52", m: "POST", mc: "m-post", path: "/graphql · stream 5", rows: [
      '<span class="h">content-type:</span> application/json',
      '<span class="h">authorization:</span> Bearer eyJhbGciOiJIUzI1NiJ9…',
      '&nbsp;',
      '{ "query": "mutation { setRole(<span class="edit">admin</span>) }" }'
    ] },
    { key: "l4", proto: "L4 · TCP", id: "#58", m: "TCP", mc: "m-tcp", path: "10.0.0.4:51514 → :5432", rows: [
      '<span class="h">44 bytes</span>&nbsp;&nbsp;in-path',
      '<span class="h">0000</span>&nbsp;&nbsp;00 00 00 2c 00 03 00 00',
      '<span class="h">0008</span>&nbsp;&nbsp;user·postgres·database·',
      '<span class="h">001f</span>&nbsp;&nbsp;<span class="edit">market_prod</span>··'
    ] }
  ];
  var protoIdx = 0, curCol = null;

  function setState(s, word) { if (!panel) return; panel.setAttribute("data-state", s); if (badge && word != null && badge.textContent !== word) badge.textContent = word; }
  function applyProto(p) {
    if (!panel) return;
    panel.setAttribute("data-proto", p.key);
    var body = p.rows.map(function (r, i) { return '<div class="flow-row" style="--i:' + (i + 1) + '">' + r + "</div>"; }).join("");
    panel.innerHTML =
      '<div class="wp-head flow-row" style="--i:0">' +
        '<span class="id">' + p.id + '</span>' +
        '<span class="wp-proto">' + p.proto + '</span>' +
        '<span class="m ' + p.mc + '">' + p.m + '</span>' +
        '<span class="path">' + p.path + '</span>' +
        '<span class="state">paused</span>' +
      '</div>' +
      '<div class="wp-body">' + body + '</div>' +
      '<div class="wp-bar flow-row" style="--i:' + (p.rows.length + 1) + '">' +
        '<span class="dot" aria-hidden="true"></span>' +
        '<span class="wp-bar-label">paused · <code>127.0.0.1:8080</code></span>' +
        '<span class="spacer"></span>' +
        '<span class="wp-act wp-act--go">Resume</span>' +
        '<span class="wp-act wp-act--kill">Kill</span>' +
      '</div>';
    badge = panel.querySelector(".state");
    curCol = (C.proto && C.proto[p.key]) || C.accent;
    for (var i = 0; i < legend.length; i++) legend[i].classList.toggle("is-active", legend[i].getAttribute("data-proto") === p.key);
  }
  function rest() { host.setAttribute("data-phase", "held"); setState("armed", "paused"); }
  if (mqReduce && mqReduce.matches) { rest(); return; }

  /* ── the canvas ────────────────────────────────────────────── */
  var cv = document.createElement("canvas"), ctx = null;
  try { ctx = cv.getContext("2d"); } catch (e) { ctx = null; }
  if (!ctx) { rest(); return; }
  cv.className = "scene-canvas"; cv.setAttribute("aria-hidden", "true");
  host.insertBefore(cv, host.firstChild);
  host.setAttribute("data-canvas", "");

  /* ── colour, read from the stylesheet so both themes hold ───── */
  var C = {}, tints = {};
  function parseColor(s) {
    s = (s || "").trim();
    var m = /^#([0-9a-f]{3,8})$/i.exec(s);
    if (m) { var h = m[1]; if (h.length < 6) h = h.split("").map(function (c) { return c + c; }).join(""); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; }
    m = /^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i.exec(s);
    return m ? [+m[1], +m[2], +m[3]] : null;
  }
  function readColors() {
    var cs = getComputedStyle(host), v = function (n, fb) { return parseColor(cs.getPropertyValue(n)) || fb; };
    C.ink = v("--ink", [17, 24, 39]); C.accent = v("--accent", [37, 99, 235]);
    C.signal = v("--signal", [217, 119, 6]); C.ok = v("--st-ok", [21, 128, 61]);
    C.agent = v("--agent", [13, 148, 136]); C.paper = v("--paper", [255, 255, 255]);
    C.proto = {
      http: v("--proto-http", [37, 99, 235]), ws: v("--proto-ws", [124, 58, 237]),
      h2: v("--proto-h2", [13, 148, 136]), l4: v("--proto-l4", [8, 145, 178])
    };
    C.dark = (0.2126 * C.paper[0] + 0.7152 * C.paper[1] + 0.0722 * C.paper[2]) / 255 < 0.5;
    if (PROTOCOLS[protoIdx]) curCol = C.proto[PROTOCOLS[protoIdx].key] || C.accent;
    tints = {};
  }
  function rgba(c, a) { return "rgba(" + (c[0] | 0) + "," + (c[1] | 0) + "," + (c[2] | 0) + "," + Math.max(0, Math.min(1, a)).toFixed(3) + ")"; }
  function mix(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]; }
  var clamp01 = function (t) { return t < 0 ? 0 : t > 1 ? 1 : t; };
  var lerp = function (a, b, t) { return a + (b - a) * t; };
  var eOutC = function (t) { return 1 - Math.pow(1 - t, 3); };
  var eOut4 = function (t) { return 1 - Math.pow(1 - t, 4); };
  var eInOut = function (t) { return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };

  var sprite = document.createElement("canvas"); sprite.width = sprite.height = 64;
  (function () {
    var c = sprite.getContext("2d"); if (!c) return;
    var g = c.createRadialGradient(32, 32, 0, 32, 32, 32);
    g.addColorStop(0, "rgba(255,255,255,1)"); g.addColorStop(0.2, "rgba(255,255,255,0.72)");
    g.addColorStop(0.5, "rgba(255,255,255,0.18)"); g.addColorStop(1, "rgba(255,255,255,0)");
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

  /* ── geometry + the plasma field ───────────────────────────── */
  var dpr = 1, cw = 0, ch = 0, G = null;
  function resize() {
    var r = cv.getBoundingClientRect(); cw = r.width; ch = r.height;
    dpr = Math.min(2, window.devicePixelRatio || 1);
    var w = Math.round(cw * dpr), h = Math.round(ch * dpr);
    /* reallocating the backing store clears the canvas — only do it on a real size change,
       not every time the panel height changes under us as protocols cycle */
    if (cv.width !== w || cv.height !== h) { cv.width = w; cv.height = h; }
    measure();
  }
  function strandY(s, x, now) { return s.baseY + s.amp * Math.sin(x / s.wl + s.ph + now * 0.001 * s.sp); }
  function strandPath(s, x0, x1, now) { ctx.beginPath(); for (var x = x0; x <= x1; x += 12) { var y = strandY(s, x, now); if (x === x0) ctx.moveTo(x, y); else ctx.lineTo(x, y); } }
  function buildField(centerY) {
    var strands = [], rows = 11, palette = [C.ink, C.accent, C.agent];
    for (var i = 0; i < rows; i++) {
      var t = (i + 0.5) / rows, baseY = lerp(0.06, 0.94, t) * ch;
      if (Math.abs(baseY - centerY) < ch * 0.05) continue;
      var depth = Math.abs(0.5 - t) * 2;
      var col = Math.random() < 0.5 ? C.ink : palette[(Math.random() * palette.length) | 0];
      var pk = [], n = 1 + ((Math.random() * 2) | 0);
      for (var j = 0; j < n; j++) pk.push({ off: Math.random(), sp: lerp(34, 16, depth) * (0.8 + Math.random() * 0.5) });
      strands.push({ baseY: baseY, amp: lerp(6, 22, Math.random()) * (0.6 + depth * 0.6), wl: lerp(120, 320, Math.random()),
        ph: Math.random() * 6.28, sp: (0.4 + Math.random() * 0.5) * (Math.random() < 0.5 ? 1 : -1),
        dim: lerp(0.3, 0.1, depth) * (col === C.ink ? 1 : 0.85), col: col, pk: pk });
    }
    return strands;
  }
  function measure() {
    /* colours must be read before the field is built — a ResizeObserver can fire before
       begin() runs readColors(); building (and caching) strands then leaves them colourless */
    if (!C.ink) return;
    var centerY = ch / 2, halfP = (panel ? panel.offsetWidth : Math.min(cw * 0.5, 520)) / 2;
    var x0 = Math.max(18, cw * 0.03), x1 = cw - x0, center = cw / 2;
    /* keep the plasma field stable when only the panel height changes (it does, each cycle,
       as protocols with different row counts recentre); rebuild it only on a real canvas resize */
    var strands = (G && G._cw === cw && G._ch === ch) ? G.strands : buildField(centerY);
    G = { centerY: centerY, x0: x0, x1: x1, center: center, panelL: center - halfP, panelR: center + halfP, strands: strands, _cw: cw, _ch: ch };
  }

  /* the hero wire's two foreground segments, in viewport pixels, for intro.js to fly into */
  window.aitmWireTarget = function () {
    if (!ctx || (mqReduce && mqReduce.matches) || !G) return null;
    var r = host.getBoundingClientRect(), vh = window.innerHeight || 800;
    if (!(r.bottom > 40 && r.top < vh - 40)) return null;
    var y = r.top + G.centerY;
    return { in: { a: [r.left + G.x0, y], b: [r.left + G.panelL, y] }, out: { a: [r.left + G.panelR, y], b: [r.left + G.x1, y] } };
  };

  /* ── timeline ──────────────────────────────────────────────── */
  var PH = { arrive: 1500, build: 1100, held: 3000, release: 1400, done: 1200, idle: 1100 };
  var NEXT = { arrive: "build", build: "held", held: "release", release: "done", done: "idle", idle: "arrive" };
  var phase = null, t0 = 0, dur = 0, trail = [], blooms = [], ingest = [];
  function bloom(x, y, c, scale) { blooms.push({ x: x, y: y, c: c, age: 0, dur: 860, r: 110 * scale, ring: 62 * scale }); }

  function enter(p, now) {
    phase = p; dur = PH[p]; t0 = now; trail = [];
    host.setAttribute("data-phase", p);
    if (p === "arrive") setState("building", "—");
    else if (p === "build") {
      applyProto(PROTOCOLS[protoIdx]);                 /* this cycle's message type */
      protoIdx = (protoIdx + 1) % PROTOCOLS.length;    /* next cycle shows the next one */
      setState("building", "building…");
      ingest = []; for (var i = 0; i < 10; i++) ingest.push({ t: i / 10, off: (Math.random() - 0.5) * 18, sp: 0.6 + Math.random() * 0.5 });
    }
    else if (p === "held") setState("armed", "paused");
    else if (p === "release") setState("resuming", "resuming…");
    else if (p === "done") { setState("done", "200"); if (G) bloom(G.x1, G.centerY, C.ok, 0.7); }
    else if (p === "idle") setState("armed", "—");
  }

  function draw(now, u, dt) {
    if (!G) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, cw, ch);
    var lum = C.dark ? 1.3 : 1, glowOp = C.dark ? "lighter" : "source-over";
    var x0 = G.x0, x1 = G.x1, cY = G.centerY, pL = G.panelL, pR = G.panelR, span = x1 - x0;

    /* 1 — the plasma field: glowing undulating strands + their packets */
    G.strands.forEach(function (s) {
      ctx.globalCompositeOperation = glowOp; ctx.lineCap = "round";
      ctx.strokeStyle = rgba(s.col, 1); ctx.lineWidth = 11; ctx.globalAlpha = s.dim * 0.4 * lum; strandPath(s, x0, x1, now); ctx.stroke();
      ctx.lineWidth = 4; ctx.globalAlpha = s.dim * 0.7 * lum; strandPath(s, x0, x1, now); ctx.stroke();
      ctx.globalCompositeOperation = "source-over"; ctx.lineWidth = 1.1; ctx.globalAlpha = Math.min(1, s.dim * 1.3); strandPath(s, x0, x1, now); ctx.stroke(); ctx.globalAlpha = 1;
    });
    G.strands.forEach(function (s) {
      s.pk.forEach(function (p) {
        var x = x0 + ((((now * p.sp / 1000) + p.off * span) % span) + span) % span, y = strandY(s, x, now);
        ctx.globalCompositeOperation = glowOp; blob(s.col, x, y, 7, 0.26 * lum);
        ctx.globalCompositeOperation = "source-over"; dot(s.col, x, y, 1.7, s.dim * 3.4);
      });
    });

    /* 2 — the foreground wire (crisp), split by the panel */
    ctx.globalCompositeOperation = "source-over"; ctx.lineCap = "round"; ctx.lineWidth = 2.5;
    ctx.strokeStyle = rgba(C.ink, C.dark ? 0.98 : 0.92);
    ctx.beginPath(); ctx.moveTo(x0, cY); ctx.lineTo(pL, cY); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(pR, cY); ctx.lineTo(x1, cY); ctx.stroke();

    /* 3 — the choreography on the foreground wire */
    var head = null;
    var inCol = curCol || C.accent;
    if (phase === "arrive") { head = { x: lerp(x0, pL, eOut4(u)), c: inCol, from: x0 }; }
    else if (phase === "release") { head = { x: lerp(pR, x1, eInOut(u)), c: mix(C.signal, C.ok, clamp01((u - 0.25) / 0.6)), from: pR }; }

    if (head) {
      ctx.globalCompositeOperation = glowOp;
      var g = ctx.createLinearGradient(head.from, cY, head.x, cY);
      g.addColorStop(0, rgba(head.c, 0)); g.addColorStop(1, rgba(head.c, 0.8));
      ctx.strokeStyle = g; ctx.lineCap = "round";
      ctx.lineWidth = 9; ctx.globalAlpha = 0.14 * lum; ctx.beginPath(); ctx.moveTo(head.from, cY); ctx.lineTo(head.x, cY); ctx.stroke();
      ctx.lineWidth = 2.5; ctx.globalAlpha = 1; ctx.beginPath(); ctx.moveTo(head.from, cY); ctx.lineTo(head.x, cY); ctx.stroke();
      ctx.globalCompositeOperation = "source-over";
    }
    var lastT = trail.length ? trail[trail.length - 1] : null;
    if (head && (!lastT || Math.abs(head.x - lastT.x) >= 3)) { trail.push({ x: head.x, c: head.c }); if (trail.length > 22) trail.shift(); }
    else if (!head && trail.length) trail.splice(0, 2);
    ctx.globalCompositeOperation = glowOp;
    for (var i = 0; i < trail.length; i++) { var T = trail[i], w = (i + 1) / (trail.length + 1); blob(T.c, T.x, cY, 3 + 9 * w, 0.34 * w * w * lum); }

    if (phase === "build") {
      ctx.globalCompositeOperation = glowOp; blob(inCol, pL, cY, 24, 0.3 * lum * (0.7 + 0.3 * Math.sin(now / 240)));
      ingest.forEach(function (p) {
        var pp = (u * p.sp + p.t) % 1, x = lerp(pL - 26, pL + 10, pp), y = cY + p.off * (1 - pp);
        blob(inCol, x, y, 5, 0.4 * (1 - pp) * lum);
        ctx.globalCompositeOperation = "source-over"; dot(inCol, x, y, 1.4, (1 - pp) * 0.9); ctx.globalCompositeOperation = glowOp;
      });
    }
    if (phase === "held") {
      var pulse = 0.7 + 0.3 * Math.sin(now / 430);
      ctx.globalCompositeOperation = glowOp; blob(C.signal, pL, cY, 26, 0.3 * lum * pulse);
      ctx.globalCompositeOperation = "source-over"; ctx.strokeStyle = rgba(C.signal, 1); ctx.lineWidth = 3; ctx.lineCap = "round";
      ctx.beginPath(); ctx.moveTo(pL, cY - 12); ctx.lineTo(pL, cY + 12); ctx.stroke(); dot(C.signal, pL, cY, 4, 1);
    }
    if (phase === "release") { ctx.globalCompositeOperation = glowOp; blob(C.signal, pR, cY, 18, 0.26 * lum * (1 - u)); }

    /* 4 — blooms (the 200 at the server) */
    ctx.globalCompositeOperation = glowOp;
    for (var b = blooms.length - 1; b >= 0; b--) {
      var B = blooms[b]; B.age += dt; var be = clamp01(B.age / B.dur), re = eOutC(be);
      if (be >= 1) { blooms.splice(b, 1); continue; }
      blob(B.c, B.x, B.y, 12 + B.r * re, (C.dark ? 0.5 : 0.38) * Math.pow(1 - be, 1.4) * lum);
      ctx.globalAlpha = 0.55 * Math.pow(1 - be, 1.2); ctx.strokeStyle = rgba(B.c, 1); ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(B.x, B.y, 5 + B.ring * re, 0, 6.2832); ctx.stroke();
    }

    /* 5 — the packet head */
    if (head) {
      ctx.globalCompositeOperation = glowOp; blob(head.c, head.x, cY, 18, 0.62 * lum);
      ctx.globalCompositeOperation = "source-over"; dot(C.ink, head.x, cY, 4.4, 1);
      if (C.dark) dot([255, 255, 255], head.x, cY, 2, 0.85);
    }
    ctx.globalAlpha = 1; ctx.globalCompositeOperation = "source-over";
  }

  /* ── the clock: pausable, kept on the beat ──────────────────── */
  var raf = 0, last = 0, pausedAt = 0, started = false, visible = !document.hidden, onScreen = true;
  function frame(now) {
    raf = requestAnimationFrame(frame);
    var dt = last ? Math.min(48, now - last) : 16; last = now;
    var guard = 0;
    while (now - t0 >= dur && guard++ < 8) { var over = now - t0 - dur; enter(NEXT[phase], now - Math.min(over, 120)); }
    draw(now, clamp01((now - t0) / dur), dt);
  }
  function run() { if (raf || !started) return; var now = performance.now(); if (pausedAt) { t0 += now - pausedAt; pausedAt = 0; } last = 0; raf = requestAnimationFrame(frame); }
  function halt() { if (!raf) return; cancelAnimationFrame(raf); raf = 0; pausedAt = performance.now(); }
  function sync() { if (visible && onScreen) run(); else halt(); }
  function inView() { var r = host.getBoundingClientRect(), vh = window.innerHeight || 800; return r.bottom > 0 && r.top < vh; }
  function begin(first) {
    if (started) return; started = true;
    readColors(); resize();
    onScreen = inView();
    enter(first || "arrive", performance.now());
    sync();
  }

  document.addEventListener("visibilitychange", function () { visible = !document.hidden; sync(); });
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (es) { es.forEach(function (e) { onScreen = e.isIntersecting; if (onScreen && !started && !siteIntro) begin(); else if (started) sync(); }); }, { threshold: 0.12 }).observe(host);
  }
  if ("ResizeObserver" in window) {
    new ResizeObserver(function () { resize(); }).observe(host);
    /* the panel's height changes every cycle; recompute geometry only, don't touch the canvas buffer */
    if (panel) new ResizeObserver(function () { measure(); }).observe(panel);
  }
  else window.addEventListener("resize", resize);
  if (mqDark && mqDark.addEventListener) mqDark.addEventListener("change", readColors);
  if (mqReduce && mqReduce.addEventListener) mqReduce.addEventListener("change", function (e) {
    if (!e.matches) return; halt(); started = true;
    if (cv.parentNode) cv.parentNode.removeChild(cv); host.removeAttribute("data-canvas"); rest();
  });

  /* ── first run: take over from the site introduction when there is one ─────
     if the mark flew into this wire, the request builds where it landed; if the
     introduction was skipped or never ran, a request simply arrives. */
  var siteIntro = html.classList.contains("intro-on");
  function fromSiteIntro(d) { if (started) return; begin(d && d.morphed ? "build" : "arrive"); }
  if (siteIntro) {
    window.addEventListener("aitm:intro", function (e) { fromSiteIntro(e.detail || window.aitmIntro); });
    if (window.aitmIntro) fromSiteIntro(window.aitmIntro);
    setTimeout(function () { fromSiteIntro(null); }, 4200);
  } else {
    requestAnimationFrame(function () { if (!started && inView()) begin(); });
    setTimeout(function () { if (!started) begin(); }, 1600);
  }
})();
