// obsync admin page. Same origin as the API; the session is an HttpOnly
// cookie set by /admin/api/login/finish. WebAuthn options arrive in the
// standard JSON form; browsers that cannot parse that form get a manual
// base64url conversion below.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var sections = ["loading", "unsupported", "no-key", "register", "login", "home"];

  function show(id) {
    sections.forEach(function (s) { $(s).classList.toggle("hidden", s !== id); });
  }
  function error(msg) {
    var el = $("error");
    if (!msg) { el.classList.add("hidden"); el.textContent = ""; return; }
    el.textContent = msg;
    el.classList.remove("hidden");
  }
  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function parseCreation(pk) {
    if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(pk);
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user.id = b64urlToBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return pk;
  }
  function parseRequest(pk) {
    if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(pk);
    pk.challenge = b64urlToBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return pk;
  }
  function credentialJSON(cred) {
    if (typeof cred.toJSON === "function") return cred.toJSON();
    var r = cred.response, out = { id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type, response: {}, clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {} };
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    out.response.clientDataJSON = bufToB64url(r.clientDataJSON);
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64url(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = bufToB64url(r.authenticatorData);
      out.response.signature = bufToB64url(r.signature);
      out.response.userHandle = r.userHandle ? bufToB64url(r.userHandle) : null;
    }
    return out;
  }
  function api(method, path, body) {
    return fetch(path, {
      method: method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
      cache: "no-store"
    }).then(function (res) {
      if (res.status === 204) return {};
      return res.json().catch(function () { return {}; }).then(function (j) {
        if (!res.ok) throw new Error(j.error || ("HTTP " + res.status));
        return j;
      });
    });
  }
  function when(ms) {
    if (!ms) return "never";
    return new Date(ms).toLocaleString();
  }
  function busy(btn, on) {
    btn.disabled = on;
    if (on) { btn.dataset.label = btn.textContent; btn.textContent = "Waiting for the key…"; }
    else if (btn.dataset.label) btn.textContent = btn.dataset.label;
  }

  var registerToken = location.pathname.replace(/\/+$/, "").endsWith("/admin/register") && location.hash.length > 1 ? location.hash.slice(1) : "";
  if (registerToken) history.replaceState(null, "", "/admin/register"); // out of the address bar and the history

  function refresh() {
    error("");
    return api("GET", "/admin/api/state").then(function (st) {
      $("origin").textContent = st.origin || location.origin;
      if (!window.PublicKeyCredential) { show("unsupported"); return; }
      if (registerToken) { show("register"); return; }
      if (st.logged_in) { renderHome(st); show("home"); return; }
      show(st.registered ? "login" : "no-key");
    }).catch(function (e) { show("loading"); error(e.message); });
  }

  function renderHome(st) {
    var vb = $("vaults").querySelector("tbody");
    vb.textContent = "";
    (st.vaults || []).forEach(function (v) {
      var tr = document.createElement("tr");
      [ "code:" + v.vault_id, String(v.devices || 0), String(v.seq), when(v.created_at) ].forEach(function (c) {
        var td = document.createElement("td");
        if (c.indexOf("code:") === 0) { var code = document.createElement("code"); code.textContent = c.slice(5); td.appendChild(code); }
        else td.textContent = c;
        tr.appendChild(td);
      });
      vb.appendChild(tr);
    });
    if (!(st.vaults || []).length) {
      var tr = document.createElement("tr"), td = document.createElement("td");
      td.colSpan = 4; td.className = "hint"; td.textContent = "No vaults yet.";
      tr.appendChild(td); vb.appendChild(tr);
    }
    var kb = $("keys").querySelector("tbody");
    kb.textContent = "";
    (st.keys || []).forEach(function (k) {
      var tr = document.createElement("tr");
      [k.name, when(k.created_at), when(k.last_used)].forEach(function (c) {
        var td = document.createElement("td"); td.textContent = c; tr.appendChild(td);
      });
      kb.appendChild(tr);
    });
    $("link-box").classList.add("hidden");
  }

  $("register-btn").addEventListener("click", function () {
    var btn = this;
    error("");
    busy(btn, true);
    api("POST", "/admin/api/register/begin", { token: registerToken }).then(function (r) {
      return navigator.credentials.create({ publicKey: parseCreation(r.options.publicKey) }).then(function (cred) {
        return api("POST", "/admin/api/register/finish", { token: registerToken, ceremony: r.ceremony, name: $("key-name").value, credential: credentialJSON(cred) });
      });
    }).then(function (r) {
      registerToken = "";
      busy(btn, false);
      error("");
      return refresh().then(function () { error("Registered " + r.name + ". Sign in with it to continue."); });
    }).catch(function (e) { busy(btn, false); error(e.message || String(e)); });
  });

  $("login-btn").addEventListener("click", function () {
    var btn = this;
    error("");
    busy(btn, true);
    api("POST", "/admin/api/login/begin").then(function (r) {
      return navigator.credentials.get({ publicKey: parseRequest(r.options.publicKey) }).then(function (cred) {
        return api("POST", "/admin/api/login/finish", { ceremony: r.ceremony, credential: credentialJSON(cred) });
      });
    }).then(function () { busy(btn, false); return refresh(); })
      .catch(function (e) { busy(btn, false); error(e.message || String(e)); });
  });

  $("logout-btn").addEventListener("click", function () {
    api("POST", "/admin/api/logout").then(refresh, function (e) { error(e.message); });
  });

  $("create-btn").addEventListener("click", function () {
    var btn = this;
    error("");
    btn.disabled = true;
    api("POST", "/admin/api/create-link").then(function (r) {
      btn.disabled = false;
      var qr = $("qr");
      qr.textContent = "";
      // The SVG is generated by this server from the link it just minted;
      // parse it as markup and keep only the svg element.
      var doc = new DOMParser().parseFromString(r.qr_svg, "image/svg+xml");
      var svg = doc.documentElement;
      if (svg && svg.nodeName === "svg") qr.appendChild(document.importNode(svg, true));
      $("open-link").setAttribute("href", r.open_url);
      $("link-text").textContent = r.link;
      $("expires").textContent = "Valid until " + when(r.expires_at) + ", once. The server has no record of the link's text; if it is lost, create another.";
      $("link-box").classList.remove("hidden");
      $("copy-btn").onclick = function () {
        navigator.clipboard.writeText(r.link).then(function () { $("copy-btn").textContent = "Copied"; setTimeout(function () { $("copy-btn").textContent = "Copy"; }, 1500); });
      };
    }).catch(function (e) { btn.disabled = false; error(e.message); });
  });

  refresh();
})();
