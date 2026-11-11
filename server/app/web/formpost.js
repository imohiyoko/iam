// OAuth 2.0 Form Post Response Mode の画面（ADR 0124）。読み終えたらフォームを連携先へ送る（スクリプトが無効ならボタン）。
"use strict";
document.addEventListener("DOMContentLoaded", function () {
  var form = document.getElementById("formpost");
  if (form) {
    form.submit();
  }
});
