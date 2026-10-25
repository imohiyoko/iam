#!/usr/bin/env bash
# ベンチマークの結果（go test -bench の出力）を bench/baseline.txt の上限と比べる。
# 使い方: go test -run '^$' -bench . ./... | scripts/benchcheck.sh bench/baseline.txt
# 同じ名前が複数回あれば（-count）中央値を使う。基準値に無いベンチマークは表示だけする。
set -euo pipefail
baseline="${1:?baseline file}"
results="$(mktemp)"
trap 'rm -f "$results"' EXIT
tee /dev/stderr | awk '/^Benchmark/ && $4 == "ns/op" { sub(/-[0-9]+$/, "", $1); print $1, $3 }' > "$results"

status=0
while read -r name max _; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  values="$(awk -v n="$name" '$1 == n { print $2 }' "$results" | sort -n)"
  if [[ -z "$values" ]]; then
    echo "MISSING  $name (no result)"; status=1; continue
  fi
  count="$(wc -l <<<"$values")"
  median="$(sed -n "$(( (count + 1) / 2 ))p" <<<"$values")"
  if awk -v m="$median" -v x="$max" 'BEGIN { exit !(m > x) }'; then
    echo "FAIL     $name median=${median}ns/op > max=${max}ns/op"; status=1
  else
    echo "ok       $name median=${median}ns/op (max ${max})"
  fi
done < "$baseline"
exit $status
