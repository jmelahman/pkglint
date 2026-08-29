// Roster controls for the report card index: text filter, grade filter (driven
// by the corpus bar and its legend), and column sorting. No dependencies; the
// table is fully readable with JavaScript off.
//
// The index server-renders only the most-voted slice of the corpus — the whole
// of it would be a quarter of a million DOM nodes — so this file also fetches
// roster.json and, once it lands, filters and sorts over every package rather
// than the rows that happen to be in the document. Until then, and with
// JavaScript off, the served rows are what there is; the alphabetical pages
// under roster/ are how the rest is reached without any of this.
(function () {
  "use strict";

  var table = document.getElementById("roster");
  if (!table) return;

  // Announce that the controls are live. Without this class the stylesheet
  // hides the search box and leaves the legend as a plain key, so nothing on
  // the page offers an interaction it cannot perform.
  document.documentElement.classList.add("js");

  var body = table.tBodies[0];
  var search = document.getElementById("q");
  var clear = document.getElementById("clear");
  var count = document.getElementById("count");
  var empty = document.getElementById("empty");
  var rest = document.getElementById("rest");
  var bar = document.querySelector(".bar");
  var keys = Array.prototype.slice.call(document.querySelectorAll(".band, .gkey"));
  var grades = Object.create(null); // selected grades; empty means "all"

  // Where package pages sit relative to this one. The script renders rows the
  // server never sent, so it has to spell their links itself, and the shards
  // that share this file are a directory deeper than the index.
  var root = table.dataset.root || "";
  // The corpus behind the table, which is not the number of rows in it.
  var total = +table.dataset.total || 0;

  // maxRows caps how many rows are ever in the document. It matches what the
  // server renders, so the opening view is exactly the table that was served
  // and costs nothing to keep; past that it is what stops a query matching
  // half the AUR from building half the AUR.
  var maxRows = 1000;

  // An entry is one package: what its row displays, plus the two case-folded
  // haystacks the filter matches against. Folding them once, here, is what
  // lets a keystroke scan the whole corpus instead of the served rows.
  //
  // The maintainer has no column, so it is not in the row's text — it is
  // folded in by hand, or the thing people most often look a package up by is
  // the thing the filter cannot find. The co-maintainers arrive the same way,
  // as one space-joined string, and go into the same haystacks: a
  // co-maintainer can push to the package just as the maintainer can, so a
  // query for who maintains it has to find them too. Both keep their own
  // haystack as well, for the "@" query, and their real casing for display.
  function entry(name, grade, findings, votes, desc, maintainer, drift, comaint) {
    var m = maintainer || "";
    var co = comaint || "";
    return {
      name: name, grade: grade, findings: findings, votes: votes,
      desc: desc || "", maintainer: m, comaint: co, drift: !!drift,
      mtext: (m + " " + co).toLowerCase(),
      text: (grade + " " + name + " " + findings + " " + votes + " " +
        (desc || "") + " " + m + " " + co).toLowerCase()
    };
  }

  // Seed from the served rows, so the controls work before roster.json lands
  // and keep working if it never does.
  var model = Array.prototype.map.call(body.rows, function (tr) {
    return entry(tr.dataset.name, tr.dataset.grade, +tr.dataset.findings,
      +tr.dataset.votes, tr.cells[4] ? tr.cells[4].textContent : "",
      tr.dataset.maintainer, tr.querySelector(".drift"), tr.dataset.comaintainers);
  });
  var loaded = false;   // roster.json has replaced the seeded model
  var sortCol = null;   // null means "the order it was served in"
  var sortDir = 1;
  // Whether the document still holds the server's rows. While it does and
  // nothing is filtering or sorting, rendering would rebuild them identically.
  var asServed = true;

  // buildRow mirrors the rostertable template. The name goes into the href
  // unescaped on purpose: selectSeed has already restricted bases to
  // alphanumerics and @._+-, none of which mean anything in a path segment,
  // and encoding them would spell a link to a file that is not there.
  // maintainedBy mirrors siteResult.MaintainedBy in Go: the tooltip that lets
  // a row matched on a handle say why, spelled once for the rows this script
  // builds exactly as the server spells it for the rows it sent.
  function maintainedBy(e) {
    var parts = [];
    if (e.maintainer) parts.push("maintained by " + e.maintainer);
    if (e.comaint) parts.push("co-maintained by " + e.comaint.split(" ").join(", "));
    return parts.join(", ");
  }

  function buildRow(e) {
    var tr = document.createElement("tr");
    tr.dataset.grade = e.grade;
    tr.dataset.name = e.name;
    tr.dataset.maintainer = e.maintainer;
    tr.dataset.comaintainers = e.comaint;
    tr.dataset.findings = e.findings;
    tr.dataset.votes = e.votes;

    var gcell = document.createElement("td");
    gcell.className = "gcell";
    var grade = document.createElement("span");
    grade.className = "grade grade-" + e.grade;
    grade.textContent = e.grade;
    gcell.appendChild(grade);

    var pkg = document.createElement("td");
    pkg.className = "pkg";
    var who = maintainedBy(e);
    if (who) pkg.title = who;
    var link = document.createElement("a");
    link.href = root + "package/" + e.name + ".html";
    link.textContent = e.name;
    pkg.appendChild(link);
    if (e.drift) {
      var warn = document.createElement("span");
      warn.className = "drift";
      warn.title = "source drift since the previous scan";
      warn.textContent = "⚠";
      pkg.appendChild(document.createTextNode(" "));
      pkg.appendChild(warn);
    }

    var findings = document.createElement("td");
    findings.className = "num";
    findings.textContent = e.findings;

    var votes = document.createElement("td");
    votes.className = "num votes";
    votes.textContent = e.votes;

    var desc = document.createElement("td");
    desc.className = "desc";
    desc.title = e.desc;
    desc.textContent = e.desc;

    tr.appendChild(gcell);
    tr.appendChild(pkg);
    tr.appendChild(findings);
    tr.appendChild(votes);
    tr.appendChild(desc);
    return tr;
  }

  function render(hits, n) {
    var frag = document.createDocumentFragment();
    for (var i = 0; i < n; i++) frag.appendChild(buildRow(hits[i]));
    body.textContent = "";
    body.appendChild(frag);
    asServed = false;
  }

  var order = ["F", "D", "C", "B", "A", "?"];
  var value = {
    grade: function (e) { return order.indexOf(e.grade); },
    name: function (e) { return e.name; },
    findings: function (e) { return e.findings; },
    votes: function (e) { return e.votes; }
  };

  function apply() {
    // A leading "@" narrows the query to who maintains the package — the
    // maintainer and every co-maintainer alike. Handles and package names
    // share one namespace on the AUR, and plenty of packages are named after
    // the person who maintains them, so a plain query cannot separate
    // "packages called foo" from "packages by foo". What follows the "@" is
    // still a substring, so "@dberm" finds dbermond; a bare "@" narrows to
    // nothing in particular and shows everything, same as an empty box.
    var raw = search ? search.value.trim() : "";
    var byMaintainer = raw.charAt(0) === "@";
    var q = (byMaintainer ? raw.slice(1) : raw).toLowerCase();
    var picked = Object.keys(grades);

    var hits = [];
    for (var i = 0; i < model.length; i++) {
      var e = model[i];
      var hay = byMaintainer ? e.mtext : e.text;
      if ((!q || hay.indexOf(q) !== -1) && (!picked.length || grades[e.grade])) {
        hits.push(e);
      }
    }
    if (sortCol) {
      var get = value[sortCol], dir = sortDir;
      hits.sort(function (a, b) {
        var x = get(a), y = get(b);
        if (x < y) return -dir;
        if (x > y) return dir;
        return a.name < b.name ? -1 : 1;
      });
    }

    var shown = Math.min(hits.length, maxRows);
    // Nothing is filtering or sorting and the served rows are still in place,
    // so they are already this exact slice — rebuilding them would be work
    // whose only effect is to throw away the HTML that was shipped.
    if (!(asServed && !q && !picked.length && !sortCol)) render(hits, shown);

    var of = loaded ? model.length : total || model.length;
    if (count) {
      if (shown < hits.length) {
        count.textContent = "first " + shown + " of " + hits.length + " matches";
      } else if (hits.length === of) {
        count.textContent = of + " packages";
      } else {
        count.textContent = hits.length + " of " + of + " packages";
      }
    }
    if (empty) empty.hidden = hits.length !== 0;
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

  // The query lives in the URL as well as the box: ?search=@lone_wolf opens
  // the roster already narrowed, which is the only way a static site can hand
  // out a link to a filtered view — a maintainer pointing at their own
  // packages being the case that pays for it. Typing mirrors the box back
  // with replaceState, one entry, so the address bar always names the view on
  // screen and Back still leaves the page rather than un-typing the query.
  function reflect() {
    if (!search || !window.URLSearchParams || !window.history ||
      !history.replaceState) return;
    var params = new URLSearchParams(location.search);
    var raw = search.value.trim();
    if (raw) params.set("search", raw);
    else params.delete("search");
    var qs = params.toString();
    history.replaceState(null, "",
      location.pathname + (qs ? "?" + qs : "") + location.hash);
  }

  if (search && window.URLSearchParams) {
    var seeded = new URLSearchParams(location.search).get("search");
    if (seeded) search.value = seeded;
  }

  if (search) {
    search.addEventListener("input", function () {
      reflect();
      apply();
    });
  }

  if (clear) {
    clear.addEventListener("click", function () {
      if (search) search.value = "";
      grades = Object.create(null);
      reflect();
      apply();
      if (search) search.focus();
    });
  }

  // Sorting. Numeric columns sort high-to-low first, text columns A-to-Z; the
  // grade column sorts worst-first, which is the order worth seeing.
  var firstDir = { grade: 1, name: 1, findings: -1, votes: -1 };

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
      sortCol = key;
      sortDir = dir;
      apply();
    });
  });

  apply();

  // The whole corpus, fetched after the page is usable rather than shipped
  // inside it. Until this lands the filter reaches the served rows only, which
  // is why the roster says so and links the alphabetical pages; if it never
  // lands, that is exactly where the page stays.
  if (rest && rest.dataset.roster && window.fetch) {
    fetch(rest.dataset.roster, { credentials: "omit" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (rows) {
        if (!rows || !rows.length) return;
        model = rows.map(function (r) {
          return entry(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
        });
        loaded = true;
        rest.textContent = "Searching all " + model.length + " packages. ";
        var link = document.createElement("a");
        link.href = root + "roster/index.html";
        link.textContent = "Browse alphabetically";
        rest.appendChild(link);
        rest.appendChild(document.createTextNode("."));
        apply();
      })
      .catch(function () {
        // Offline, blocked, or truncated: the served rows remain the roster.
      });
  }
})();
