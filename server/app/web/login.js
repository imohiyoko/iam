// ホスト型ログイン画面（design.md 2.5）。公開 API の上に作り、同じオリジンの Cookie でセッションを受け取る。
// トークンは URL のフラグメント（#token=...）で受け取り、サーバーのログと Referer に残さない。
"use strict";

(function () {
  const app = document.getElementById("app");
  const messages = JSON.parse(document.getElementById("messages").textContent || "{}");
  const msg = document.getElementById("message");
  // realm を /realms/{slug} で指すときの接頭辞（ADR 0083）。API と戻り先に付ける。
  const base = app.dataset.base || "";

  function show(step) {
    for (const s of document.querySelectorAll("[data-step]")) s.hidden = s.dataset.step !== step;
  }

  function say(code, isError) {
    if (!code) {
      msg.textContent = "";
      msg.className = "";
      return;
    }
    // realm で足した停止の種別には、共通の文言を出す。
    const fallback = code.startsWith("suspended.") ? messages.suspended : messages.error;
    msg.textContent = messages[code] || fallback || code;
    msg.className = isError ? "error" : "";
  }

  async function post(path, body) {
    const res = await fetch(base + path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* 本文が無い */ }
    return { ok: res.ok, status: res.status, data };
  }

  function fail(r) {
    say((r.data && r.data.error) || "error", true);
  }

  // 戻り先は同じオリジンのパスだけを許す（オープンリダイレクトを防ぐ）。URL の解析はタブや改行を
  // 取り除くため（"/\t/evil.example" は "//evil.example" になる）、制御文字とバックスラッシュを拒み、
  // 解決した結果のオリジンも確かめる。返すのは絶対 URL にする。パスだけを返すと、ドット区間の正規化で
  // "/a/..//evil.example" の pathname が "//evil.example" になり、遷移のときに外部の URL と解釈される。
  // 外部プロバイダへの往復では戻り先がクエリから消えるので、同じタブの sessionStorage に預ける。
  function returnTo() {
    let r = app.dataset.returnTo || "";
    try {
      if (r) sessionStorage.setItem("iam_return_to", r);
      else if (app.dataset.page === "oauth_callback") r = sessionStorage.getItem("iam_return_to") || "";
    } catch (_) {}
    return r;
  }

  function safeReturnTo() {
    const r = returnTo();
    if (!r.startsWith("/") || /[\u0000-\u001f\u007f\\]/.test(r)) return "";
    try {
      const u = new URL(r, window.location.origin);
      return u.origin === window.location.origin ? u.href : "";
    } catch (_) {
      return "";
    }
  }

  function done(r) {
    if (!r.ok) return fail(r);
    // 2要素目を求められたら、認証器アプリのコードを聞く（passkey の2要素目と登録は公開 API で行う。ADR 0050）。
    if (r.data.next === "second_factor") {
      if ((r.data.second_factor_methods || []).includes("totp") && document.getElementById("totp-form")) {
        say("", false);
        show("totp");
        document.getElementById("totp").focus();
        return;
      }
      show("done");
      return say("second_factor_unsupported", true);
    }
    if (r.data.next === "enroll") {
      show("done");
      return say("enroll_required", true);
    }
    show("done");
    say((r.data.warnings || []).length ? "warnings" : "done", false);
    const to = safeReturnTo();
    try { sessionStorage.removeItem("iam_return_to"); } catch (_) {}
    if (to) window.location.assign(to);
  }

  function fragmentToken() {
    const p = new URLSearchParams(window.location.hash.slice(1));
    history.replaceState(null, "", window.location.pathname + window.location.search);
    return p.get("token") || "";
  }

  const emailForm = document.getElementById("email-form");
  if (emailForm) {
    emailForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const r = await post("/v1/login/email:start", { email: document.getElementById("email").value });
      if (!r.ok) return fail(r);
      say("", false);
      show("code");
      document.getElementById("code").focus();
    });
  }

  const codeForm = document.getElementById("code-form");
  if (codeForm) {
    codeForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      done(await post("/v1/login/email:verify", { code: document.getElementById("code").value }));
    });
  }

  const totpForm = document.getElementById("totp-form");
  if (totpForm) {
    totpForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      done(await post("/v1/login/second-factor:verify", { totp_code: document.getElementById("totp").value }));
    });
  }

  const restart = document.getElementById("restart");
  if (restart) restart.addEventListener("click", () => { say("", false); show("email"); });

  for (const b of document.querySelectorAll(".provider")) {
    b.addEventListener("click", async () => {
      const redirect = window.location.origin + base + "/login/oauth/callback";
      const r = await post("/v1/login/oauth/" + encodeURIComponent(b.dataset.connection) + ":start", { redirect_uri: redirect });
      if (!r.ok) return fail(r);
      window.location.assign(r.data.authorization_url);
    });
  }

  switch (app.dataset.page) {
    case "oauth_callback": {
      const q = new URLSearchParams(window.location.search);
      history.replaceState(null, "", window.location.pathname);
      if (q.get("error") || !q.get("state") || !q.get("code")) { show("email"); say("authentication_failed", true); break; }
      show("pending");
      post("/v1/login/oauth:complete", { state: q.get("state"), code: q.get("code") }).then((r) => {
        if (!r.ok) show("email");
        done(r);
      });
      break;
    }
    case "link": {
      const token = fragmentToken();
      show("pending");
      post("/v1/login/link:redeem", { token }).then((r) => { if (!r.ok) show("email"); done(r); });
      break;
    }
    case "magic_link": {
      // メールのリンク。要求したブラウザ（フローの Cookie を持つ）でだけ通る（4.1）。
      const token = fragmentToken();
      show("pending");
      post("/v1/login/email:verify", { token }).then((r) => { if (!r.ok) show("email"); done(r); });
      break;
    }
    default:
      show("email");
  }
})();
