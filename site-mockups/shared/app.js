/* Small, honest interactions for the mockups. Content works without JS. */
(function () {
  "use strict";

  // --- the two operators: same command, two origins ---
  var HUMAN = {
    file: "operator · terminal",
    code:
      '<span class="op">$</span> aitm flow mutate --id 42 --set-body \'{"sku":"A-1042","qty":999}\'\n' +
      '<span class="cm"># parked at request · edit applied · flow.resume to forward</span>',
  };
  var AGENT = {
    file: "agent · MCP tool call",
    code:
      '<span class="pr">flow.mutate</span>(<span class="op">{</span> <span class="pr">id</span>: <span class="num">42</span>, <span class="pr">set_body</span>: <span class="str">\'{"sku":"A-1042","qty":999}\'</span> <span class="op">}</span>)\n' +
      '<span class="cm"># origin: mcp · same command, logged to the audit trail</span>',
  };
  var tabs = document.querySelectorAll(".op-tab");
  var codeEl = document.getElementById("op-code");
  var fileEl = document.getElementById("op-file");
  function setOp(which) {
    var d = which === "agent" ? AGENT : HUMAN;
    if (codeEl) codeEl.querySelector("code").innerHTML = d.code;
    if (fileEl) fileEl.textContent = d.file;
    tabs.forEach(function (t) {
      t.setAttribute("aria-selected", String(t.dataset.op === which));
    });
  }
  tabs.forEach(function (t) {
    t.addEventListener("click", function () { setOp(t.dataset.op); });
  });

  // --- hero intercept actions ---
  var actions = document.getElementById("hero-actions");
  if (actions) {
    var row = document.querySelector(".hero .ui-row.armed");
    var status = actions.querySelector("[data-status]");
    var resume = actions.querySelector("[data-resume]");
    var kill = actions.querySelector("[data-kill]");
    function settle(text, cls) {
      if (!row) return;
      row.classList.remove("armed");
      var s = row.querySelector(".ui-s");
      s.className = "ui-s " + cls;
      s.textContent = text;
      var t = row.querySelector(".ui-t");
      if (t) t.textContent = cls === "ok" ? "24ms" : "reset";
      if (status) status.textContent = cls === "ok" ? "forwarded with edits" : "connection reset";
    }
    if (resume) resume.addEventListener("click", function () { settle("200", "ok"); });
    if (kill) kill.addEventListener("click", function () { settle("RST", "armed"); });
  }

  // --- reveal on scroll ---
  if (matchMedia("(prefers-reduced-motion: no-preference)").matches) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("is-in"); io.unobserve(e.target); } });
    }, { threshold: 0.12 });
    document.querySelectorAll("[data-reveal]").forEach(function (el) { io.observe(el); });
  }
})();
