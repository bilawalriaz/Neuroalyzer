# NER performance: measurements and open work

NER is experimental. This page records what was measured on the way to 2.1.0 and what is left, so the next round starts from data. All numbers are from an M3 Pro (6 performance + 6 efficiency cores, 36 GB) over 6.1 GB of real agent sessions (11,981 files), unless noted.

## Where 2.1.0 stands

| | 2.0.0 | 2.1.0 |
|---|---|---|
| `scan --no-ner`, whole corpus | 168.7 s, 34.6 MB/s | 38.6 s, 151.0 MB/s |
| NER, Gemini sessions (89 files, 4,143 chunks inferred) | 105.3 s, 39 chunks/s | 69.7 s, 59 chunks/s |
| NER, whole corpus (1.09 M unique chunks) | ~13-18 h (projected) | ~5 h (projected from chunks/s) |

NER findings are identical to 2.0.0 (`bench/compare.py`). What changed for NER: one corpus-wide collect pass with global dedup, then a lock-free pool of model workers (one single-threaded worker per physical core, sharing one ONNX Runtime session), longest chunks first, with ONNX Runtime spin-waiting off.

## What the profile showed

- The corpus has 3.3 M prose chunks, 1.09 M unique. 44% of unique chunks are under 16 model words, about 10% are 256+.
- Cost per chunk (one session, 6 threads): 7.6 ms under 16 words, 16 ms at 32-63, 28 ms at 64-127, 57 ms at 128-255, 370 ms at 256-511. The long tail is most of the time.
- About 2.3% of unique chunks are over 512 model words. The model truncates at 512 tokens, so the end of those chunks is never read. This is a recall gap that 2.0.0 also has (see below).
- CPU inference is near the int8 throughput of the cores; the remaining wins are less work, not faster math.

## Tried and dropped

| Idea | Result |
|---|---|
| Batching, length-sorted | No gain on short chunks; 10x slower on long ones, 11.5 GB RSS at batch 16. The export's span head grows with words², and it has an LSTM. Default stays 1. |
| CoreML execution provider (ort 2.0.0-rc.9, dynamic shapes) | 0.35-0.45x of CPU speed on the quint8 model, 0.25-0.3x on fp32. Still available via `--features coreml --ner-device coreml`. |
| fp32 model on CPU | 0.4-0.45x of quint8. |
| fp16 model | The published `model_fp16.onnx` fails to load (type mismatch at the embeddings Cast). |
| One session with 6 threads vs workers | 1 x 6 was the slowest layout (34 chunks/s); 12 x 1 the fastest (59). |
| Smaller chunks (64-128 model words, overlap) | No speedup (the text that used to be truncated now gets read), and more false positives on the fixture set: decoys redacted rose from 2 to 21-39 of 1,107. |
| Re-cutting only chunks that overflow 512 tokens | Fixes the truncation gap but costs ~35% on Gemini and redacted 5 decoys vs 2. Left out of 2.1.0; needs a decision. |

## Open work, in order of expected payoff

1. **Persistent NER cache.** Repeat runs would infer only new chunks (session data is append-mostly), and an interrupted run would keep its work. A module is drafted on the local branch `wip/ner-persistent-cache`: keyed BLAKE3 chunk ids (a plain hash of a short chunk could be confirmed by guessing), an append-only log per fingerprint of model, labels, threshold and chunking, and torn-tail recovery. Left: wire it into `ner.rs`, add `--no-ner-cache` and `cache clear`, and tests.
2. **NER progress in the bar.** The infer stage already reports chunks done/total and chunks/s, with an ETA in model words. Show cache hits once the cache lands.
3. **Fast tier.** `knowledgator/gliner-pii-edge-v1.0` (token mode) ran 2.4-4.2x faster than the base model, and `-small` 1.2-1.7x. Both need a token-mode decoder: their logits are `[classes, batch, words, 3]`, not what gline-rs expects. Accuracy against the base model is still to be measured on the fixture set.
4. **Truncation gap.** Decide whether the recall gain on over-long chunks is worth the time and the extra decoys (see above).
5. **Junk gating.** On 400 long chunks, skipping chunks where under 20% of tokens are words cut 15% of model work and lost no person, address or DOB detections, but did lose some org detections. Needs a labelled set before it can be on by default.
6. **GPU.** A fixed-shape fp16 export and a newer `ort` (MLProgram, static shapes) might make CoreML pay off. Uncertain: the LSTM is a poor fit for the Neural Engine. CUDA and DirectML are wired up behind cargo features but not benchmarked.

## Reproducing

```sh
cargo build --release
bench/bench.py target/release/neuralyzer --root ~/scrub-test --modes no-ner,cold,warm
bench/compare.py bench/reports/<old>.json bench/reports/<new>.json
```

`bench/bench.py` needs the model already downloaded; point `NEURALYZER_MODEL_DIR` at it.
