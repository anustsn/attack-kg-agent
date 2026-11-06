"""Command line: ``attackkg fetch | build | stats | sparql | triage``."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import config


def _load_kg(path: str | None):
    from .kg import KnowledgeGraph

    kg_file = Path(path) if path else config.kg_path()
    if not kg_file.exists():
        sys.exit(f"Knowledge graph not found at {kg_file}. Run `attackkg fetch` and `attackkg build` first.")
    return KnowledgeGraph.from_turtle(kg_file)


def cmd_fetch(args) -> None:
    from .fetch import fetch_all

    print(json.dumps(fetch_all(force=args.force), indent=2))


def cmd_build(args) -> None:
    from .stix2rdf import build

    src = Path(args.stix) if args.stix else config.attack_json_path()
    if not src.exists():
        sys.exit(f"{src} not found. Run `attackkg fetch` first.")
    t0 = time.time()
    info = build(src, Path(args.out) if args.out else config.kg_path())
    info["seconds"] = round(time.time() - t0, 1)
    print(json.dumps(info, indent=2))


def cmd_stats(args) -> None:
    print(json.dumps(_load_kg(args.kg).stats(), indent=2))


def cmd_sparql(args) -> None:
    query = Path(args.query).read_text(encoding="utf-8") if Path(args.query).is_file() else args.query
    for row in _load_kg(args.kg).sparql(query):
        print("\t".join("" if v is None else str(v) for v in row))


def cmd_triage(args) -> None:
    from .agent import SYSTEM_PROMPT, TOOLS, triage, triage_offline
    from .alerts import Alert
    from .llm import make_session

    kg = _load_kg(args.kg)
    results = []
    for path in args.alerts:
        alert = Alert.load(path)
        if args.backend == "offline":
            res = triage_offline(kg, alert)
        else:
            session = make_session(args.backend, SYSTEM_PROMPT.format(version=kg.version), TOOLS,
                                   model=args.model, effort=args.effort)
            res = triage(kg, alert, session, max_steps=args.max_steps, seed=not args.no_seed)
        results.append(res)
        _print_result(kg, alert, res)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps([r.to_dict() for r in results], indent=2), encoding="utf-8")
        print(f"\nFull results with the agent's trace: {out}")


def cmd_bench(args) -> None:
    from . import bench, evaluate
    from .llm import UsageLimitReached

    run_dir = Path(args.dir)
    if args.action == "report":
        _, summary = evaluate.report(run_dir)
        print(summary)
        return
    kg = _load_kg(args.kg)
    if args.action == "build":
        zip_path = config.sigma_zip_path()
        if not zip_path.exists():
            sys.exit(f"{zip_path} not found. Run `attackkg fetch` first.")
        info = bench.build(kg, zip_path, config.benchmark_path(), config.SIGMA_RELEASE, n=args.n or 300, seed=args.seed)
        print(json.dumps(info, indent=2))
        return
    items = bench.load(config.benchmark_path(), args.n or 100)
    try:
        evaluate.run(kg, items, args.system, run_dir / f"{args.system}.jsonl", backend=args.backend,
                     model=args.model, effort=args.effort, workers=args.workers)
    except UsageLimitReached as e:
        sys.exit(f"Stopped: {e}\nFinished items are saved; run the same command again later to continue.")


def _print_result(kg, alert, res) -> None:
    print(f"\n=== {alert.id}: {alert.title}")
    print(f"status: {res.status}  (model calls: {res.llm_calls}, submissions: {res.submissions})"
          + (f"  {res.detail}" if res.detail else ""))
    for m in res.mappings:
        tactic = m.get("tactic", "")
        print(f"  {m['technique_id']:<10} {kg.full_name(m['technique_id'])}  [{tactic}]  conf={m.get('confidence')}")
        if via := m.get("observed_via"):
            more = f" (+{len(via) - 2} more)" if len(via) > 2 else ""
            print(f"             observed via: {'; '.join(v[:90] for v in via[:2])}{more}")
        if m.get("rationale"):
            print(f"             {m['rationale']}")
    for w in res.warnings:
        print(f"  warning ({w['technique_id']}): {w['message']}")
    for r in res.rejected:
        print(f"  rejected {r['mapping'].get('technique_id')}: " + "; ".join(f['message'] for f in r['findings']))
    if alert.gold:
        got = {m["technique_id"] for m in res.mappings}
        print(f"  expected: {', '.join(alert.gold)}  ->  {'match' if got & set(alert.gold) else 'no match'}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="attackkg", description=__doc__)
    p.add_argument("--kg", help=f"knowledge graph file (default {config.kg_path()})")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("fetch", help="download ATT&CK and Sigma at the pinned versions")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_fetch)

    s = sub.add_parser("build", help="convert the ATT&CK STIX bundle into the RDF knowledge graph")
    s.add_argument("--stix")
    s.add_argument("--out")
    s.set_defaults(func=cmd_build)

    s = sub.add_parser("stats", help="print knowledge graph statistics")
    s.set_defaults(func=cmd_stats)

    s = sub.add_parser("sparql", help="run a SPARQL query (a string or a .rq file)")
    s.add_argument("query")
    s.set_defaults(func=cmd_sparql)

    s = sub.add_parser("triage", help="map alerts to ATT&CK techniques")
    s.add_argument("alerts", nargs="+", help="alert JSON files")
    s.add_argument("--backend", choices=["claude-cli", "anthropic", "offline"], default="claude-cli")
    s.add_argument("--model", default=config.DEFAULT_MODEL)
    s.add_argument("--effort", default=config.DEFAULT_EFFORT, choices=["low", "medium", "high", "xhigh", "max"])
    s.add_argument("--max-steps", type=int, default=10)
    s.add_argument("--no-seed", action="store_true", help="do not give the agent keyword-search candidates")
    s.add_argument("--out", help="write full results (with trace) to this JSON file")
    s.set_defaults(func=cmd_triage)

    s = sub.add_parser("bench", help="build the Sigma benchmark, run a system on it, or report scores")
    s.add_argument("action", choices=["build", "run", "report"])
    s.add_argument("system", nargs="?", default="offline",
                   choices=["offline", "closed-book", "closed-book+repair", "agent"])
    s.add_argument("--n", type=int, help="items to build (default 300) or to run (default 100)")
    s.add_argument("--seed", type=int, default=13)
    s.add_argument("--backend", choices=["claude-cli", "anthropic"], default="claude-cli")
    s.add_argument("--model", default=config.DEFAULT_MODEL)
    s.add_argument("--effort", default=config.DEFAULT_EFFORT, choices=["low", "medium", "high", "xhigh", "max"])
    s.add_argument("--workers", type=int, default=1, help="alerts processed in parallel")
    s.add_argument("--dir", default="results/benchmark", help="where results are written")
    s.set_defaults(func=cmd_bench)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
