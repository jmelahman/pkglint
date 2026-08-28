// Roster controls for the report card index: text filter, grade filter (driven
// by the corpus bar and its legend), and column sorting. No dependencies; the
// table is fully readable with JavaScript off.
(function () {
  "use strict";

  var table = document.getElementById("roster");
  if (!table) return;

  // Announce that the controls are live. Without this class the stylesheet
  // hides the search box and leaves the legend as a plain key, so nothing on
  // the page offers an interaction it cannot perform.
  document.documentElement.classList.add("js");

  var body = table.tBodies[0];
  var rows = Array.prototype.slice.call(body.rows);
  var search = document.getElementById("q");
  var clear = document.getElementById("clear");
  var count = document.getElementById("count");
  var empty = document.getElementById("empty");
  var bar = document.querySelector(".bar");
  var keys = Array.prototype.slice.call(document.querySelectorAll(".band, .gkey"));
  var grades = Object.create(null); // selected grades; empty means "all"

  rows.forEach(function (tr) {
    // The maintainer has no column, so it is not in the row's text — fold it in
    // by hand, or the one thing people most often look a package up by is the
    // one thing the filter cannot find. Both haystacks are cached case-folded,
    // under their own keys: data-maintainer keeps the handle's real casing,
    // which is what the page renders and what a reader of the DOM expects.
    var maintainer = (tr.dataset.maintainer || "").toLowerCase();
    tr.dataset.maintainerText = maintainer;
    tr.dataset.text = (tr.textContent + " " + maintainer).toLowerCase();
  });

  function selected() {
    return Object.keys(grades);
  }

  function apply() {
    // A leading "@" narrows the query to the maintainer. Handles and package
    // names share one namespace on the AUR, and plenty of packages are named
    // after the person who maintains them, so a plain query cannot separate
    // "packages called foo" from "packages by foo". What follows the "@" is
    // still a substring, so "@dberm" finds dbermond; a bare "@" narrows to
    // nothing in particular and shows everything, same as an empty box.
    var raw = search ? search.value.trim() : "";
    var byMaintainer = raw.charAt(0) === "@";
    var q = (byMaintainer ? raw.slice(1) : raw).toLowerCase();
    var picked = selected();
    var shown = 0;
    rows.forEach(function (tr) {
      var hay = byMaintainer ? tr.dataset.maintainerText : tr.dataset.text;
      var ok = (!q || hay.indexOf(q) !== -1) &&
        (!picked.length || grades[tr.dataset.grade]);
      tr.hidden = !ok;
      if (ok) shown++;
    });
    if (count) {
      count.textContent = shown === rows.length
        ? rows.length + " packages"
        : shown + " of " + rows.length + " packages";
    }
    if (empty) empty.hidden = shown !== 0;
    // raw, not q: a box holding just "@" filters nothing but is still not
    // empty, and Reset is what empties it.
    if (clear) clear.hidden = !raw && !picked.length;
    if (bar) bar.classList.toggle("filtered", picked.length > 0);
    keys.forEach(function (el) {
      el.setAttribute("aria-pressed", grades[el.dataset.grade] ? "true" : "false");
    });
  }

  keys.forEach(function (el) {
    el.addEventListener("click", function () {
      var g = el.dataset.grade;
      if (grades[g]) delete grades[g];
      else grades[g] = true;
      apply();
    });
  });

  if (search) search.addEventListener("input", apply);

  if (clear) {
    clear.addEventListener("click", function () {
      if (search) search.value = "";
      grades = Object.create(null);
      apply();
      if (search) search.focus();
    });
  }

  // Sorting. Numeric columns sort high-to-low first, text columns A-to-Z; the
  // grade column sorts worst-first, matching the page's default order.
  var order = ["F", "D", "C", "B", "A", "?"];
  var firstDir = { grade: 1, name: 1, findings: -1, votes: -1 };
  var value = {
    grade: function (tr) { return order.indexOf(tr.dataset.grade); },
    name: function (tr) { return tr.dataset.name; },
    findings: function (tr) { return +tr.dataset.findings; },
    votes: function (tr) { return +tr.dataset.votes; }
  };

  Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th) {
    var key = th.dataset.sort;
    if (!key || !value[key]) return;
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = th.textContent;
    th.textContent = "";
    th.appendChild(button);
    button.addEventListener("click", function () {
      var cur = th.getAttribute("aria-sort");
      var dir = cur ? (cur === "ascending" ? -1 : 1) : firstDir[key];
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function (o) {
        o.removeAttribute("aria-sort");
      });
      th.setAttribute("aria-sort", dir === 1 ? "ascending" : "descending");
      var get = value[key];
      rows.sort(function (a, b) {
        var x = get(a), y = get(b);
        if (x < y) return -dir;
        if (x > y) return dir;
        return a.dataset.name < b.dataset.name ? -1 : 1;
      });
      var frag = document.createDocumentFragment();
      rows.forEach(function (tr) { frag.appendChild(tr); });
      body.appendChild(frag);
    });
  });

  apply();
})();
