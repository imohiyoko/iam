// WS-Federation のトークンを RP の wreply へ送る画面（ADR 0110）。読み終えたらフォームを送る（スクリプトが無効ならボタン）。
"use strict";
document.addEventListener("DOMContentLoaded", function () {
  var form = document.getElementById("wsfed");
  if (form) {
    form.submit();
  }
});
