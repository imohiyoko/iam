// ログアウトの完了画面（ADR 0094）。Front-Channel Logout の iframe を読み終えたら（最長 5 秒）、連携先の戻り先に移る。
// head で同期に読み、iframe の load を document の捕捉の段で数える（iframe が先に読み終えても数え漏らさない）。
"use strict";
(function () {
  var loaded = 0;
  var total = -1;
  var done = false;
  var target = "";
  function go() {
    if (!done && target) {
      done = true;
      window.location.replace(target);
    }
  }
  document.addEventListener("load", function (e) {
    if (e.target && e.target.tagName === "IFRAME") {
      loaded++;
      if (total >= 0 && loaded >= total) {
        go();
      }
    }
  }, true);
  document.addEventListener("DOMContentLoaded", function () {
    var main = document.getElementById("logout");
    target = (main && main.getAttribute("data-redirect")) || "";
    total = document.querySelectorAll("iframe").length;
    if (loaded >= total) {
      go();
    } else {
      window.setTimeout(go, 5000);
    }
  });
})();
