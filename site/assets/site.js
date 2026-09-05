// Roster controls for the report card index: text filter, grade filter (driven
// by the corpus bar and its legend), repository filter (driven by the
// breakdown table and the official-repositories toggle), and column sorting. No dependencies; the table is fully
// readable with JavaScript off.
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
  var bars = Array.prototype.slice.call(document.querySelectorAll(".bar"));
  var keys = Array.prototype.slice.call(document.querySelectorAll(".band, .gkey"));
  var rkeys = Array.prototype.slice.call(document.querySelectorAll(".rkey"));
  // The official-repositories toggle, and the blocks that show one scope of
  // the corpus — the whole of it or the AUR alone. Both exist only when the
  // corpus has two sources; with one, every repository control is absent
  // and the filter defaults to everything, as it always did.
  var official = document.getElementById("official");
  var scoped = Array.prototype.slice.call(document.querySelectorAll("[data-scope]"));
  var grades = Object.create(null); // selected grades; empty means "all"
  var repos = Object.create(null);  // selected repositories; empty means "all"

  // aurOnly is the toggle's off position: exactly the AUR selected. It is
  // the default when the toggle exists — the masthead says AUR, so the
  // official repositories are the opt-in — and the AUR scope of the numbers
  // above the roster is shown for as long as it holds. Any other selection,
  // including none, is the toggle on and the whole-corpus scope.
  function aurOnly() {
    var rs = Object.keys(repos);
    return rs.length === 1 && rs[0] === "aur";
  }
  function defaultRepos() {
    var rs = Object.create(null);
    if (official) rs.aur = true;
    return rs;
  }

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
  // An official package has a packager where an AUR package has a
  // maintainer, and the packager goes where the maintainer would.
  function entry(name, grade, findings, votes, desc, maintainer, drift, comaint, repo, packager) {
    var m = maintainer || "";
    var co = comaint || "";
    var r = repo || "aur";
    var p = packager || "";
    return {
      name: name, grade: grade, findings: findings, votes: votes,
      desc: desc || "", maintainer: m, comaint: co, drift: !!drift,
      repo: r, packager: p, official: r !== "aur",
      mtext: (m + " " + co + " " + p).toLowerCase(),
      text: (grade + " " + name + " " + r + " " + findings + " " + votes + " " +
        (desc || "") + " " + m + " " + co + " " + p).toLowerCase()
    };
  }

  // Seed from the served rows, so the controls work before roster.json lands
  // and keep working if it never does.
  var model = Array.prototype.map.call(body.rows, function (tr) {
    return entry(tr.dataset.name, tr.dataset.grade, +tr.dataset.findings,
      +tr.dataset.votes, tr.cells[5] ? tr.cells[5].textContent : "",
      tr.dataset.maintainer, tr.querySelector(".drift"), tr.dataset.comaintainers,
      tr.dataset.repo, tr.dataset.packager);
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
    if (e.official) return e.packager ? "packaged by " + e.packager : "";
    var parts = [];
    if (e.maintainer) parts.push("maintained by " + e.maintainer);
    if (e.comaint) parts.push("co-maintained by " + e.comaint.split(" ").join(", "));
    return parts.join(", ");
  }

  function buildRow(e) {
    var tr = document.createElement("tr");
    tr.dataset.grade = e.grade;
    tr.dataset.name = e.name;
    tr.dataset.repo = e.repo;
    tr.dataset.maintainer = e.maintainer;
    tr.dataset.comaintainers = e.comaint;
    tr.dataset.packager = e.packager;
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

    var rcell = document.createElement("td");
    rcell.className = "rcell";
    var repo = document.createElement("span");
    repo.className = "repo repo-" + e.repo;
    repo.textContent = e.repo;
    rcell.appendChild(repo);

    var findings = document.createElement("td");
    findings.className = "num";
    findings.textContent = e.findings;

    var votes = document.createElement("td");
    votes.className = "num votes";
    if (e.official) {
      var none = document.createElement("span");
      none.className = "none";
      none.textContent = "\u2013";
      votes.appendChild(none);
    } else {
      votes.textContent = e.votes;
    }

    var desc = document.createElement("td");
    desc.className = "desc";
    desc.title = e.desc;
    desc.textContent = e.desc;

    tr.appendChild(gcell);
    tr.appendChild(pkg);
    tr.appendChild(rcell);
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
  // Repositories sort as the Go side ranks them (repoRank): the base system
  // first, the AUR last, anything unfamiliar between.
  var repoOrder = ["core", "extra", "multilib"];
  function repoRank(r) {
    if (r === "aur") return repoOrder.length + 1;
    var i = repoOrder.indexOf(r);
    return i < 0 ? repoOrder.length : i;
  }
  var value = {
    grade: function (e) { return order.indexOf(e.grade); },
    name: function (e) { return e.name; },
    repo: function (e) { return repoRank(e.repo); },
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
    var rpicked = Object.keys(repos);

    var hits = [];
    // inScope counts what the repository selection alone admits: the
    // denominator the query and the grade keys narrow from, so an AUR-only
    // view reads as so many packages rather than so many matches.
    var inScope = 0;
    for (var i = 0; i < model.length; i++) {
      var e = model[i];
      if (rpicked.length && !repos[e.repo]) continue;
      inScope++;
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
    if (!(asServed && !q && !picked.length && !rpicked.length && !sortCol)) render(hits, shown);

    // Until roster.json lands the served rows are a slice of the corpus, and
    // the page's own total is the honest denominator for it.
    var of = loaded || rpicked.length ? inScope : total || model.length;
    if (count) {
      if (shown < hits.length) {
        count.textContent = "first " + shown + " of " + hits.length +
          (hits.length === of ? " packages" : " matches");
      } else if (hits.length === of) {
        count.textContent = of + " packages";
      } else {
        count.textContent = hits.length + " of " + of + " packages";
      }
    }
    if (empty) empty.hidden = hits.length !== 0;
    // raw, not q: a box holding just "@" filters nothing but is still not
    // empty, and Reset is what empties it.
    var atDefault = official ? aurOnly() : !rpicked.length;
    if (clear) clear.hidden = !raw && !picked.length && atDefault;
    bars.forEach(function (el) { el.classList.toggle("filtered", picked.length > 0); });
    if (official) {
      official.checked = !aurOnly();
      scoped.forEach(function (el) {
        el.hidden = (el.dataset.scope === "aur") !== aurOnly();
      });
    }
    keys.forEach(function (el) {
      el.setAttribute("aria-pressed", grades[el.dataset.grade] ? "true" : "false");
    });
    rkeys.forEach(function (el) {
      el.setAttribute("aria-pressed", repos[el.dataset.repo] ? "true" : "false");
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

  rkeys.forEach(function (el) {
    el.addEventListener("click", function () {
      var r = el.dataset.repo;
      if (repos[r]) delete repos[r];
      else repos[r] = true;
      reflect();
      apply();
    });
  });

  if (official) {
    official.addEventListener("change", function () {
      repos = Object.create(null);
      if (!official.checked) repos.aur = true;
      reflect();
      apply();
    });
  }

  // The query lives in the URL as well as the box: ?search=@lone_wolf opens
  // the roster already narrowed, which is the only way a static site can hand
  // out a link to a filtered view — a maintainer pointing at their own
  // packages being the case that pays for it. ?repo=core does the same for
  // the repository filter, so "how does core look" is a link too. When the
  // toggle exists its off position is the page's default and goes unspelled;
  // ?repo=all is the toggle on with nothing narrower picked. Typing
  // mirrors the box back with replaceState, one entry, so the address bar
  // always names the view on screen and Back still leaves the page rather
  // than un-typing the query.
  function reflect() {
    if (!window.URLSearchParams || !window.history || !history.replaceState) return;
    var params = new URLSearchParams(location.search);
    var raw = search ? search.value.trim() : "";
    if (raw) params.set("search", raw);
    else params.delete("search");
    var rs = Object.keys(repos);
    if (official && aurOnly()) params.delete("repo");
    else if (official && !rs.length) params.set("repo", "all");
    else if (rs.length) params.set("repo", rs.join(","));
    else params.delete("repo");
    var qs = params.toString();
    history.replaceState(null, "",
      location.pathname + (qs ? "?" + qs : "") + location.hash);
  }

  repos = defaultRepos();
  if (window.URLSearchParams) {
    var params = new URLSearchParams(location.search);
    var seeded = params.get("search");
    if (search && seeded) search.value = seeded;
    // Only repositories the page knows: an unknown one would select nothing
    // and show an empty roster with no key to un-press.
    var known = Object.create(null);
    rkeys.forEach(function (el) { known[el.dataset.repo] = true; });
    var wanted = params.get("repo") || "";
    if (wanted === "all") {
      repos = Object.create(null);
    } else if (wanted) {
      repos = Object.create(null);
      wanted.split(",").forEach(function (r) {
        if (known[r]) repos[r] = true;
      });
      if (!Object.keys(repos).length) repos = defaultRepos();
    }
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
      repos = defaultRepos();
      reflect();
      apply();
      if (search) search.focus();
    });
  }

  // Sorting. Numeric columns sort high-to-low first, text columns A-to-Z; the
  // grade column sorts worst-first, which is the order worth seeing.
  var firstDir = { grade: 1, name: 1, repo: 1, findings: -1, votes: -1 };

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
          return entry(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]);
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
