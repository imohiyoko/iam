#!/usr/bin/env bash
# リポジトリ内の Go モジュールごとにコマンドを実行する（各アダプタは別モジュール。ADR 0015）。
# 使い方: scripts/modules.sh go test -race ./...
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off
status=0
for m in . adapters/storage/sqlite cmd/iam spikes; do
  echo "::group::$m: $*"
  (cd "$m" && "$@") || status=1
  echo "::endgroup::"
done
exit $status
