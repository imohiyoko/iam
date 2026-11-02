// SAML の Response・LogoutResponse を SP へ送る画面（ADR 0115）。読み終えたらフォームを送る（スクリプトが無効ならボタン）。
"use strict";
document.addEventListener("DOMContentLoaded", function () {
  var form = document.getElementById("samlidp");
  if (form) {
    form.submit();
  }
});
