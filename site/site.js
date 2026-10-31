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

  /* Operating system: install steps are tagged [data-for-os="macos"|"linux"], and
     html[data-os] decides which show (CSS hides the other; "all" shows both). The
     default comes from the visitor's platform, and each [data-os-switch] lets them
     override it. Without JS every path stays visible and the switch stays hidden. */
  var detectOS = function () {
    var plat = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    var ua = navigator.userAgent || "";
    if (/mac/i.test(plat) || /Macintosh/.test(ua)) return "macos";
    if (/Android/.test(ua)) return "all";
    if (/linux/i.test(plat) || /Linux/.test(ua)) return "linux";
    return "all";
  };
  var detectArch = function () {
    return /aarch64|arm64|armv8/i.test(navigator.userAgent || "") ? "aarch64" : "x86_64";
  };
  var setOS = function (os) {
    document.documentElement.setAttribute("data-os", os);
    document.querySelectorAll("[data-os-pick]").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-os-pick") === os ? "true" : "false");
    });
  };
  var osSwitches = document.querySelectorAll("[data-os-switch]");
  if (osSwitches.length) {
    setOS(detectOS());
    osSwitches.forEach(function (sw) {
      sw.removeAttribute("hidden");
      sw.addEventListener("click", function (e) {
        var pick = e.target.closest("[data-os-pick]");
        if (pick) setOS(pick.getAttribute("data-os-pick"));
      });
    });
  }

  /* Release manifest: resolve the latest release and let the page derive its
     version string, the "Get aitmproxy vX.Y.Z" label, the release-page link and
     the per-platform download table from it — so nothing here is pinned to a
     version in markup. The primary source is downloads.json, committed to site/
     by the release pipeline on every release (no network needed). If it is
     absent or unreadable we fall back to the public tap's GitHub releases API
     for live resolution. All of this is progressive enhancement: the markup
     carries a correct fallback version and the static Homebrew / build-from-source
     instructions, so if nothing resolves we change nothing and say nothing. */
  var dlHost = document.querySelector("[data-downloads]");
  var tagEls = document.querySelectorAll("[data-release-tag]");
  var urlEls = document.querySelectorAll("[data-release-url]");
  var assetEls = document.querySelectorAll("[data-asset], [data-asset-url]");
  if ((dlHost || tagEls.length || urlEls.length || assetEls.length) && window.fetch) {
    var GH_LATEST = "https://api.github.com/repos/mrbrutti/homebrew-aitmproxy/releases/latest";

    var td = function (text) {
      var cell = document.createElement("td");
      cell.textContent = text == null ? "" : String(text);
      return cell;
    };
    var shortSha = function (sha) {
      var s = sha == null ? "" : String(sha);
      return s.length > 12 ? s.slice(0, 12) + "…" : s;
    };

    /* Infer manifest fields from an asset file name, matching
       scripts/gen-downloads-manifest.sh, for the GitHub API fallback (which
       carries no platform/arch/format and no checksums of its own). */
    var formatFor = function (n) {
      if (/\.tar\.gz$/i.test(n)) return "tar.gz";
      if (/\.deb$/i.test(n)) return "deb";
      if (/\.rpm$/i.test(n)) return "rpm";
      if (/\.dmg$/i.test(n)) return "dmg";
      return null;
    };
    var platformFor = function (n) {
      if (/\.dmg$/i.test(n) || /apple-darwin/i.test(n)) return "macos";
      if (/linux/i.test(n) || /\.deb$/i.test(n) || /\.rpm$/i.test(n)) return "linux";
      return "";
    };
    var archFor = function (n) {
      if (/x86_64|amd64/i.test(n)) return "x86_64";
      if (/aarch64|arm64/i.test(n)) return "aarch64";
      if (/\.dmg$/i.test(n)) return "aarch64";
      return "";
    };
    /* Normalise a GitHub releases/latest payload into the downloads.json shape,
       keeping only recognised package/archive assets (skipping signatures,
       checksum files and anything else attached to the release). */
    var fromGitHub = function (gh) {
      if (!gh || !gh.tag_name) return null;
      var tag = String(gh.tag_name);
      var assets = (gh.assets || []).filter(function (a) {
        return a && a.name && formatFor(a.name);
      }).map(function (a) {
        return {
          platform: platformFor(a.name),
          arch: archFor(a.name),
          format: formatFor(a.name),
          name: a.name,
          url: a.browser_download_url,
          sha256: null
        };
      });
      return {
        version: tag.replace(/^v/, ""),
        tag: tag,
        release_url: gh.html_url,
        assets: assets
      };
    };

    var renderDownloads = function (data) {
      if (!dlHost || !data || !data.assets || !data.assets.length) return;
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
        if (a.url && /^https?:\/\//i.test(a.url)) {
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
      dlHost.innerHTML = "";
      dlHost.appendChild(ui);
      dlHost.removeAttribute("hidden");
    };

    /* Install commands name real assets: [data-asset="deb"] takes the file name and
       [data-asset-url="deb"] the download URL of the asset of that format for the
       platform of the enclosing [data-for-os] block (Linux when there is none) and
       the visitor's CPU. macOS assets exist for aarch64 only. */
    var assetFor = function (list, format, platform, arch) {
      var exact = null, loose = null;
      list.forEach(function (a) {
        if (!a || a.format !== format || a.platform !== platform) return;
        if (a.arch === arch) exact = exact || a;
        loose = loose || a;
      });
      return exact || loose;
    };
    var fillAssets = function (data) {
      if (!data.assets || !data.assets.length) return;
      var arch = detectArch();
      document.querySelectorAll("[data-asset], [data-asset-url]").forEach(function (el) {
        var wantUrl = el.hasAttribute("data-asset-url");
        var format = el.getAttribute(wantUrl ? "data-asset-url" : "data-asset");
        var scope = el.closest("[data-for-os]");
        var platform = scope ? scope.getAttribute("data-for-os") : "linux";
        var a = assetFor(data.assets, format, platform, platform === "macos" ? "aarch64" : arch);
        if (!a) return;
        if (wantUrl) {
          if (!a.url || !/^https?:\/\//i.test(a.url)) return;
          if (el.tagName === "A") el.setAttribute("href", a.url); else el.textContent = a.url;
        } else if (a.name) {
          el.textContent = a.name;
        }
      });
    };

    /* Apply a resolved manifest to every version/link/table consumer on the page.
       Each field is optional: a missing one leaves its markup fallback untouched. */
    var applyManifest = function (data) {
      if (!data) return;
      var tag = data.tag || (data.version ? "v" + data.version : null);
      if (tag) {
        tagEls.forEach(function (el) { el.textContent = tag; });
      }
      if (data.release_url && /^https?:\/\//i.test(data.release_url)) {
        urlEls.forEach(function (el) {
          if (el.tagName === "A") el.setAttribute("href", data.release_url);
        });
      }
      fillAssets(data);
      renderDownloads(data);
    };

    var fetchJSON = function (url, opts) {
      return window.fetch(url, opts).then(function (res) {
        return res && res.ok ? res.json() : null;
      });
    };

    try {
      fetchJSON("downloads.json", { cache: "no-cache" }).then(function (data) {
        if (data && (data.tag || data.version || (data.assets && data.assets.length))) {
          applyManifest(data);
          return;
        }
        /* Manifest missing or empty: try the public tap's releases API. */
        return fetchJSON(GH_LATEST, {
          cache: "no-cache",
          headers: { Accept: "application/vnd.github+json" }
        }).then(function (gh) { applyManifest(fromGitHub(gh)); });
      })["catch"](function () {
        /* downloads.json failed outright: last-resort live resolution. */
        return fetchJSON(GH_LATEST, {
          cache: "no-cache",
          headers: { Accept: "application/vnd.github+json" }
        }).then(function (gh) { applyManifest(fromGitHub(gh)); })["catch"](function () {
          /* nothing resolved: keep the markup fallback */
        });
      });
    } catch (e) { /* fetch threw synchronously: keep the fallback */ }
  }
})();
