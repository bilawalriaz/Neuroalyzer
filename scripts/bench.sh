#!/usr/bin/env bash
# Benchmark: generate a synthetic tree (~1 GB by default), then time scan
# without and with NER, and a clean without NER.
# Usage: scripts/bench.sh [BYTES]      (needs the NER model for the --ner run)
set -euo pipefail
BYTES="${1:-1000000000}"
OUT="${OUT:-bench-data}"
cargo build --release -q -p sesscrub -p fixturegen
rm -rf "$OUT"
mkdir -p "$OUT"
./target/release/fixturegen "$OUT/home" --bytes "$BYTES" --manifest "$OUT/manifest.json" >/dev/null
find "$OUT/home" -exec touch -t 202501010000 {} +
echo "tree: $(du -sh "$OUT/home" | cut -f1), $(find "$OUT/home" -type f | wc -l | tr -d ' ') files"
export SESSCRUB_DATA_DIR="$OUT/data" SESSCRUB_NO_KEYRING=1
summary() {
  python3 -c "import json,sys; r=json.load(open(sys.argv[1])); print(f\"{sys.argv[2]:<16} {r['elapsed_secs']:>8.1f}s {r['throughput_mb_per_sec']:>8.1f} MB/s  findings={sum(c['count'] for c in r['totals'])}  ner_chunks={r['engines']['ner_chunks_inferred']} cache_hits={r['engines']['ner_cache_hits']}\")" "$1" "$2"
}
./target/release/sesscrub scan --root "$OUT/home" --no-ner --json -q > "$OUT/scan-no-ner.json" || true
summary "$OUT/scan-no-ner.json" "scan --no-ner"
if [ "${SKIP_NER:-0}" != 1 ]; then
  ./target/release/sesscrub scan --root "$OUT/home" --ner --json -q > "$OUT/scan-ner.json" || true
  summary "$OUT/scan-ner.json" "scan --ner"
fi
printf 'benchmark-password-only\n' > "$OUT/pw" && chmod 600 "$OUT/pw"
./target/release/sesscrub clean --root "$OUT/home" --no-ner --yes --password-file "$OUT/pw" --json -q > "$OUT/clean-no-ner.json"
summary "$OUT/clean-no-ner.json" "clean --no-ner"
uname -sm
sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true
