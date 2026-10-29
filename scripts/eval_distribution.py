"""
Runs classification across a large batch of mock-enriched indicators and
reports the severity distribution. Not a correctness test (there's no
ground truth for synthetic data) — it's a sanity check that the
deterministic rules produce a reasonable, non-degenerate spread instead
of collapsing everything into one bucket, and a concrete number to point
to instead of "it probably works."

Run: python -m scripts.eval_distribution
"""

import asyncio
import logging
from collections import Counter

logging.disable(logging.WARNING)  # mock-mode warnings would otherwise flood N*2 lines

from app.classify import classify_file_hash, classify_ip
from app.enrichment import check_file_hash, check_ip

N = 2000


async def main() -> None:
    ip_counts: Counter = Counter()
    for i in range(N):
        enrichment = await check_ip(f"198.51.{i // 256}.{i % 256}")
        result = classify_ip(enrichment)
        ip_counts[result.severity.value] += 1

    hash_counts: Counter = Counter()
    for i in range(N):
        enrichment = await check_file_hash(f"eval-hash-{i}")
        result = classify_file_hash(enrichment)
        hash_counts[result.severity.value] += 1

    print(f"IP classification over {N} mock indicators:")
    for severity in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        print(f"  {severity:8s} {ip_counts.get(severity, 0):5d}  ({ip_counts.get(severity, 0) / N:.1%})")

    print(f"\nFile-hash classification over {N} mock indicators:")
    for severity in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        print(f"  {severity:8s} {hash_counts.get(severity, 0):5d}  ({hash_counts.get(severity, 0) / N:.1%})")


if __name__ == "__main__":
    asyncio.run(main())
