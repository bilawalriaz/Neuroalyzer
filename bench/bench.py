#!/usr/bin/env python3
"""Repeatable scan benchmark.

    bench/bench.py BIN [--root DIR] [--bytes N] [--modes no-ner,cold,warm] [--out results.jsonl] [-- extra scan args]

Without --root, a synthetic corpus is generated once with crates/fixturegen
(seeded, so every run sees the same bytes) under bench/.corpus/. Each mode runs
`BIN scan --json` in a fresh data directory so nothing touches your real one:

  no-ner  regex/validator detectors only
  cold    NER with an empty cache
  warm    NER again in the same data directory (persistent cache, if any)

The NER model is taken from <PKG>_MODEL_DIR, or the default data dir's models/
folder, and is never downloaded here. Results are printed as a table and
appended as JSON lines to --out, keyed by the binary's --version, so runs of an
old and a new binary can be compared. Reports are saved next to it for
bench/compare.py.
"""
import argparse, json, os, pathlib, platform, resource, shutil, subprocess, sys, tempfile, time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent


def pkg_env_prefix(binary):
    version = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    return version.split()[0].upper().replace("-", "_"), version


def default_model_dir(prefix):
    if os.environ.get(f"{prefix}_MODEL_DIR"):
        return pathlib.Path(os.environ[f"{prefix}_MODEL_DIR"])
    home = pathlib.Path.home()
    name = prefix.lower()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support"
    elif os.name == "nt":
        base = pathlib.Path(os.environ.get("LOCALAPPDATA", home))
    else:
        base = pathlib.Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))
    return base / name / "models"


def corpus(nbytes):
    root = HERE / ".corpus" / f"fixture-{nbytes}"
    if not (root / ".done").exists():
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        subprocess.run(
            ["cargo", "run", "-q", "--release", "-p", "fixturegen", "--", str(root), "--seed", "7", "--bytes", str(nbytes)],
            cwd=REPO, check=True,
        )
        (root / ".done").write_text("")
    return root


def run(binary, args, env):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.perf_counter()
    p = subprocess.run([binary, *args], env=env, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if p.returncode not in (0, 1):
        sys.exit(f"{binary} failed ({p.returncode}):\n{p.stderr[-3000:]}")
    # ru_maxrss: bytes on macOS, KiB on Linux; it is a high-water mark over all children,
    # so each mode runs in its own process tree via a fresh python child below.
    rss = after.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    return wall, cpu, rss, json.loads(p.stdout), p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--root")
    ap.add_argument("--bytes", type=int, default=200 << 20)
    ap.add_argument("--modes", default="no-ner,cold,warm")
    ap.add_argument("--out", default=str(HERE / "results.jsonl"))
    ap.add_argument("--label", default="")
    ap.add_argument("--one", help=argparse.SUPPRESS)
    ap.add_argument("extra", nargs="*")
    a = ap.parse_intermixed_args()
    binary = str(pathlib.Path(a.binary).resolve())
    prefix, version = pkg_env_prefix(binary)
    root = pathlib.Path(a.root).resolve() if a.root else corpus(a.bytes)

    if a.one:  # child process: run one mode so ru_maxrss is per mode
        data = pathlib.Path(os.environ["BENCH_DATA_DIR"])
        env = dict(os.environ)
        env.update({f"{prefix}_DATA_DIR": str(data), f"{prefix}_NO_KEYRING": "1", f"{prefix}_NO_DOWNLOAD": "1",
                    f"{prefix}_MODEL_DIR": str(default_model_dir(prefix))})
        args = ["scan", "--json", "-q", "--root", str(root), *a.extra]
        args.append("--no-ner" if a.one == "no-ner" else "--ner")
        wall, cpu, rss, rep, err = run(binary, args, env)
        e = rep.get("engines", {})
        if a.one != "no-ner" and not e.get("ner"):
            sys.exit(f"NER didn't run in mode {a.one}: {e.get('ner_note')}. Set {prefix}_MODEL_DIR to a folder with the model.")
        res = {
            "version": version, "label": a.label, "mode": a.one, "root": str(root), "host": platform.node(),
            "machine": platform.machine(), "wall_s": round(wall, 2), "cpu_s": round(cpu, 1),
            "cores_avg": round(cpu / wall, 2) if wall else 0, "peak_rss_mb": round(rss / 2**20),
            "bytes": rep.get("bytes_scanned"), "mb_per_s": round(rep.get("bytes_scanned", 0) / 2**20 / wall, 1),
            "files": rep.get("files_scanned"), "ner_inferred": e.get("ner_chunks_inferred"),
            "ner_hits": e.get("ner_cache_hits"), "extra": a.extra,
        }
        if res["ner_inferred"]:
            res["ner_chunks_per_s"] = round(res["ner_inferred"] / wall, 1)
        tot = (res["ner_inferred"] or 0) + (res["ner_hits"] or 0)
        if tot:
            res["ner_hit_rate"] = round((res["ner_hits"] or 0) / tot, 3)
        rp = pathlib.Path(a.out).resolve().parent / "reports"
        rp.mkdir(exist_ok=True)
        (rp / f"{version.replace(' ', '-')}{('-' + a.label) if a.label else ''}-{a.one}.json").write_text(json.dumps(rep))
        print(json.dumps(res))
        return

    rows = []
    with tempfile.TemporaryDirectory(prefix="bench-data-") as d:
        for mode in a.modes.split(","):
            env = dict(os.environ, BENCH_DATA_DIR=d)
            fresh = mode in ("no-ner", "cold")
            if fresh:
                shutil.rmtree(d, ignore_errors=True)
                os.makedirs(d)
            cmd = [sys.executable, __file__, a.binary, "--root", str(root), "--out", a.out, "--label", a.label, "--one", mode, "--", *a.extra]
            p = subprocess.run(cmd, env=env, capture_output=True, text=True)
            if p.returncode:
                sys.exit(p.stderr)
            res = json.loads(p.stdout.strip().splitlines()[-1])
            rows.append(res)
            with open(a.out, "a") as f:
                f.write(json.dumps(res) + "\n")
    cols = ["mode", "wall_s", "cpu_s", "cores_avg", "peak_rss_mb", "mb_per_s", "ner_inferred", "ner_hits", "ner_chunks_per_s"]
    print(f"{version} {a.label}  root={root}")
    print("  ".join(f"{c:>15}" for c in cols))
    for r in rows:
        print("  ".join(f"{str(r.get(c, '')):>15}" for c in cols))


if __name__ == "__main__":
    main()
