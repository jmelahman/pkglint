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
    tr.dataset.text = tr.textContent.toLowerCase();
  });

  function selected() {
    return Object.keys(grades);
  }

  function apply() {
    var q = search ? search.value.trim().toLowerCase() : "";
    var picked = selected();
    var shown = 0;
    rows.forEach(function (tr) {
      var ok = (!q || tr.dataset.text.indexOf(q) !== -1) &&
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
    if (clear) clear.hidden = !q && !picked.length;
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
