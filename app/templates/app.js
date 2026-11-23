/* OrbitDesk web client (excerpt of the bundled SPA). */
(function () {
  "use strict";

  // Bootstrapped for the signed-in user.
  var ME = __ORBIT_ME__;

  function api(method, path, body) {
    var options = { method: method, credentials: "include", headers: {} };
    var token = window.localStorage && localStorage.getItem("orbit_token");
    if (token) options.headers["Authorization"] = "Bearer " + token;
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return fetch(path, options).then(function (r) { return r.json(); });
  }

  var Tickets = {
    get: function (id) { return api("GET", "/api/tickets/" + id); },
    search: function (q) { return api("GET", "/api/v1/tickets/search?q=" + encodeURIComponent(q)); },
    hppSearch: function (q) { return api("GET", "/api/search-hpp?q=" + encodeURIComponent(q)); }
  };

  var Billing = {
    invoice: function (id) { return api("GET", "/api/invoices/" + id); },
    subscription: function (id) { return api("GET", "/api/subscriptions/" + id); },
    payment: function (id) { return api("GET", "/api/payments/" + id); },
    refund: function (id) { return api("GET", "/api/refunds/" + id); },
    card: function (id) { return api("GET", "/api/cards/" + id); },
    order: function (id) { return api("GET", "/api/v2/orders/" + id); },
    findOrders: function (query) { return api("POST", "/api/orders/find", query); }
  };

  var People = {
    user: function (id) { return api("GET", "/api/users/" + id); },
    customer: function (id) { return api("GET", "/api/customers/" + id); },
    member: function (id) { return api("GET", "/api/team/" + id); },
    findUsers: function (query) { return api("POST", "/api/users/find", query); },
    adminList: function () { return api("GET", "/api/admin/users"); }
  };

  var Workspace = {
    file: function (id) { return api("GET", "/api/files/" + id); },
    report: function (id) { return api("GET", "/api/reports/" + id); },
    note: function (id) { return api("GET", "/api/notes/" + id); },
    task: function (id) { return api("GET", "/api/tasks/" + id); },
    message: function (id) { return api("GET", "/api/messages/" + id); },
    document: function (id) { return api("GET", "/api/documents/" + id); },
    attachment: function (id) { return api("GET", "/api/attachments/" + id); },
    audit: function (id) { return api("GET", "/api/audit/" + id); }
  };

  var Session = {
    current: function (query) { return api("POST", "/api/session", query); },
    refresh: function () { return api("GET", "/api/token/verify2"); },
    unfurl: function (target) { return api("GET", "/api/fetch?target=" + encodeURIComponent(target)); }
  };

  // Pre-rendered fragments served from the edge cache.
  var Cache = {
    home: function () { return fetch("/cache/home").then(function (r) { return r.text(); }); },
    profile: function () { return fetch("/cache/profile").then(function (r) { return r.text(); }); },
    api: function () { return fetch("/cache/api").then(function (r) { return r.text(); }); },
    assets: function () { return fetch("/cache/assets").then(function (r) { return r.text(); }); }
  };

  function hydrate() {
    document.querySelectorAll("[data-ticket-id]").forEach(function (el) {
      Tickets.get(el.getAttribute("data-ticket-id")).then(function (t) { el.title = t.kind || ""; });
    });
    Billing.invoice(ME.invoice);
    Billing.subscription(ME.subscription);
    People.user(ME.user);
    Workspace.note(ME.note);
    Cache.home();
  }

  window.OrbitDesk = {
    me: ME, Tickets: Tickets, Billing: Billing, People: People,
    Workspace: Workspace, Session: Session, Cache: Cache
  };
  document.addEventListener("DOMContentLoaded", hydrate);
})();
