/* tvgw diagram connectors. No dependencies. build.py inlines this file into each figure.

   Markup, inside a .stage:
     <div class="wire accent" data-from="tv@r" data-to="pi@l:-24" data-label-at="above">
       every packet<span class="sub">secondary line</span>
     </div>

   data-from / data-to   "<data-id>@<side>[:<offset>]". side is t, r, b or l; offset moves the point
                         along that side in px from its middle (positive is right or down).
                         "@<x>,<y>" is a bare point in stage px.
   data-via              "x,y x,y": corner points for a route the default cannot express.
   data-align="from"     end on the start's line (a straight wire into a taller or wider node).
   data-mid              x (horizontal-horizontal) or y (vertical-vertical) of the middle leg.
   data-draw="none"      draw nothing, only place the label: a second label for the same route.
   data-start            "dot" draws an origin dot. data-end: "arrow" (default), "none", "stop", "dot".
   data-label-seg        which straight segment holds the label (default: the longest).
   data-label-t          where along it, 0..1 (default 0.5).
   data-label-at         "on" (knocked out of the line, default), "above", "below", "left", "right".
   data-label-dx/-dy     nudges in px.
   Classes on .wire      accent | strong | dashed | stop (stroke style), and are copied to the label.
   Every number is in stage px; keep them on the 8 px grid. */
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var RADIUS = 12, HEAD_L = 9, HEAD_W = 4.75, GAP = 8;

  function box(stage, el) {
    var s = stage.getBoundingClientRect(), r = el.getBoundingClientRect();
    return { x: r.left - s.left, y: r.top - s.top, w: r.width, h: r.height };
  }

  function point(stage, spec) {
    var at = spec.split("@");
    if (at[0] === "") {
      var xy = at[1].split(",");
      return { x: +xy[0], y: +xy[1], side: null };
    }
    var el = stage.querySelector('[data-id="' + at[0] + '"]');
    if (!el) throw new Error("wires: no element with data-id=" + at[0]);
    var b = box(stage, el);
    var parts = (at[1] || "r").split(":"), side = parts[0], off = +(parts[1] || 0);
    if (side === "t") return { x: b.x + b.w / 2 + off, y: b.y, side: side };
    if (side === "b") return { x: b.x + b.w / 2 + off, y: b.y + b.h, side: side };
    if (side === "l") return { x: b.x, y: b.y + b.h / 2 + off, side: side };
    return { x: b.x + b.w, y: b.y + b.h / 2 + off, side: "r" };
  }

  var horiz = function (s) { return s === "l" || s === "r"; };

  function route(a, b, w) {
    if (w.dataset.via) {
      var via = w.dataset.via.trim().split(/\s+/).map(function (p) {
        var xy = p.split(","); return { x: +xy[0], y: +xy[1] };
      });
      return [a].concat(via, [b]);
    }
    var mid = w.dataset.mid;
    /* data-align="from": keep the route straight by moving the end onto the start's line. */
    if (w.dataset.align === "from") { if (horiz(a.side)) b.y = a.y; else b.x = a.x; }
    if (horiz(a.side) && horiz(b.side)) {
      if (Math.abs(a.y - b.y) < 0.5) return [a, { x: b.x, y: a.y }];
      var mx = mid !== undefined ? +mid : (a.x + b.x) / 2;
      return [a, { x: mx, y: a.y }, { x: mx, y: b.y }, b];
    }
    if (!horiz(a.side) && !horiz(b.side)) {
      if (Math.abs(a.x - b.x) < 0.5) return [a, { x: a.x, y: b.y }];
      var my = mid !== undefined ? +mid : (a.y + b.y) / 2;
      return [a, { x: a.x, y: my }, { x: b.x, y: my }, b];
    }
    if (horiz(a.side)) return [a, { x: b.x, y: a.y }, b];
    return [a, { x: a.x, y: b.y }, b];
  }

  function dir(p, q) {
    var dx = q.x - p.x, dy = q.y - p.y, l = Math.hypot(dx, dy) || 1;
    return { x: dx / l, y: dy / l, l: l };
  }

  /* Polyline to a path with rounded corners. */
  function pathD(pts) {
    var d = "M" + pts[0].x + " " + pts[0].y;
    for (var i = 1; i < pts.length - 1; i++) {
      var p = pts[i - 1], c = pts[i], n = pts[i + 1];
      var d1 = dir(p, c), d2 = dir(c, n);
      var r = Math.min(RADIUS, d1.l / 2, d2.l / 2);
      d += " L" + (c.x - d1.x * r) + " " + (c.y - d1.y * r);
      d += " Q" + c.x + " " + c.y + " " + (c.x + d2.x * r) + " " + (c.y + d2.y * r);
    }
    var last = pts[pts.length - 1];
    return d + " L" + last.x + " " + last.y;
  }

  function el(name, attrs, parent) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    parent.appendChild(e);
    return e;
  }

  function draw(stage) {
    var svg = stage.querySelector(":scope > svg.wires");
    if (!svg) {
      svg = document.createElementNS(NS, "svg");
      svg.setAttribute("class", "wires");
      svg.setAttribute("aria-hidden", "true");
      stage.insertBefore(svg, stage.firstChild);
    }
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    stage.querySelectorAll(".wire").forEach(function (w) {
      var kinds = ["accent", "strong", "dashed", "stop"].filter(function (k) { return w.classList.contains(k); });
      var cls = kinds.join(" ");
      var a = point(stage, w.dataset.from), b = point(stage, w.dataset.to);
      /* A bare point takes the side facing the other end. */
      var across = Math.abs(b.x - a.x) >= Math.abs(b.y - a.y);
      if (!a.side) a.side = across ? (b.x > a.x ? "r" : "l") : (b.y > a.y ? "b" : "t");
      if (!b.side) b.side = across ? (b.x > a.x ? "l" : "r") : (b.y > a.y ? "t" : "b");
      var pts = route(a, b, w).filter(function (p, i, all) {
        return i === 0 || Math.abs(p.x - all[i - 1].x) > 0.5 || Math.abs(p.y - all[i - 1].y) > 0.5;
      });
      var end = w.dataset.end || (w.classList.contains("stop") ? "stop" : "arrow");

      /* Shorten the last leg so the arrowhead's tip lands exactly on the target edge. */
      var tail = dir(pts[pts.length - 2], pts[pts.length - 1]);
      var tip = pts[pts.length - 1];
      var drawn = pts.slice();
      if (end === "arrow") drawn[drawn.length - 1] = { x: tip.x - tail.x * (HEAD_L - 1), y: tip.y - tail.y * (HEAD_L - 1) };
      if (end === "stop") drawn[drawn.length - 1] = { x: tip.x - tail.x * GAP, y: tip.y - tail.y * GAP };
      var ghost = w.dataset.draw === "none";
      if (!ghost) el("path", { d: pathD(drawn), class: "w " + cls }, svg);

      if (ghost) { /* a second label on a wire drawn by another .wire */ }
      else if (end === "arrow") {
        var bx = tip.x - tail.x * HEAD_L, by = tip.y - tail.y * HEAD_L;
        el("path", {
          d: "M" + tip.x + " " + tip.y + " L" + (bx - tail.y * HEAD_W) + " " + (by + tail.x * HEAD_W) +
             " L" + (bx + tail.y * HEAD_W) + " " + (by - tail.x * HEAD_W) + " Z",
          class: "head " + cls
        }, svg);
      } else if (end === "stop") {
        var sx = tip.x - tail.x * GAP, sy = tip.y - tail.y * GAP;
        el("path", {
          d: "M" + (sx - tail.y * 8) + " " + (sy + tail.x * 8) + " L" + (sx + tail.y * 8) + " " + (sy - tail.x * 8),
          class: "head stop"
        }, svg);
      }
      if (end === "dot") {
        el("circle", { cx: tip.x, cy: tip.y, r: 3.5, class: "dot " + cls }, svg);
      }
      if (w.dataset.start === "dot") {
        el("circle", { cx: a.x, cy: a.y, r: 3.5, class: "dot " + cls }, svg);
      }

      /* The label */
      var label = w.querySelector(".wire-label");
      if (!label && w.childNodes.length) {
        label = document.createElement("div");
        label.className = "wire-label";
        while (w.firstChild) label.appendChild(w.firstChild);
        stage.appendChild(label);
        w._label = label;
      }
      label = w._label || label;
      if (!label) return;
      kinds.forEach(function (k) { if (k === "accent" || k === "stop") label.classList.add(k); });

      var segs = [];
      for (var i = 0; i < pts.length - 1; i++) segs.push({ p: pts[i], q: pts[i + 1], l: dir(pts[i], pts[i + 1]).l });
      var si = w.dataset.labelSeg !== undefined ? +w.dataset.labelSeg : segs.reduce(function (m, s, i) { return s.l > segs[m].l ? i : m; }, 0);
      var seg = segs[Math.min(si, segs.length - 1)];
      var t = w.dataset.labelT !== undefined ? +w.dataset.labelT : 0.5;
      var cx = seg.p.x + (seg.q.x - seg.p.x) * t, cy = seg.p.y + (seg.q.y - seg.p.y) * t;
      var at = w.dataset.labelAt || "on";
      label.classList.add(at === "on" ? "on" : "off");
      if (at === "on" || at === "above" || at === "below") label.classList.add(label.classList.contains("right") ? "right" : "center");
      var lw = label.offsetWidth, lh = label.offsetHeight, x, y;
      if (at === "on") { x = cx - lw / 2; y = cy - lh / 2; }
      else if (at === "above") { x = cx - lw / 2; y = cy - lh - 8; }
      else if (at === "below") { x = cx - lw / 2; y = cy + 8; }
      else if (at === "left") { x = cx - lw - 12; y = cy - lh / 2; }
      else { x = cx + 12; y = cy - lh / 2; }
      x += +(w.dataset.labelDx || 0); y += +(w.dataset.labelDy || 0);
      label.style.left = Math.round(x) + "px";
      label.style.top = Math.round(y) + "px";
    });
  }

  function drawAll() { document.querySelectorAll(".stage").forEach(draw); document.documentElement.dataset.wired = "1"; }

  /* Theme from the URL: #dark or #light forces it; #render hides captions for the PNG. */
  var h = location.hash;
  if (/dark/.test(h)) document.documentElement.dataset.theme = "dark";
  if (/light/.test(h)) document.documentElement.dataset.theme = "light";
  if (/render/.test(h)) document.addEventListener("DOMContentLoaded", function () { document.body.classList.add("render"); });

  var go = function () { (document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve()).then(drawAll); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", go); else go();
  window.tvgwWires = { draw: draw, drawAll: drawAll };
})();
