from __future__ import annotations

import argparse
from uuid import uuid4
from pathlib import Path

from app.logger import log_agent_output
from app.agents import analyzer, classifier, reporter


def read_input_text(path: str | None) -> str:
    # Si no nos pasan --input, usamos el template por defecto
    if not path:
        default_path = Path(__file__).resolve().parents[1] / "inputs" / "template_input.txt"
        return default_path.read_text(encoding="utf-8")

    p = Path(path)
    return p.read_text(encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="MELI DataSec Challenge - Day 1 skeleton")
    parser.add_argument("--input", help="Path a un archivo de texto para usar como input", default=None)
    args = parser.parse_args()

    session_id = uuid4().hex  # simple y único
    text = read_input_text(args.input)

    # Agentes fake
    analyzer_out = analyzer.run(session_id=session_id, text=text)
    classifier_out = classifier.run(session_id=session_id, analyzer_out=analyzer_out)
    reporter_out = reporter.run(session_id=session_id, analyzer_out=analyzer_out, classifier_out=classifier_out)

    # Logs por agente
    p1 = log_agent_output(session_id, "analyzer", analyzer_out)
    p2 = log_agent_output(session_id, "classifier", classifier_out)
    p3 = log_agent_output(session_id, "reporter", reporter_out)

    print(f"Session: {session_id}")
    print(f"Logs:")
    print(f" - {p1}")
    print(f" - {p2}")
    print(f" - {p3}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
