from __future__ import annotations

import numpy as np

from consultation_kb.generation.c1_provider import (
    DeterministicGenerationC1Provider,
)
from consultation_kb.mcp.runtime import ProductionRuntime
from consultation_kb.mcp.server import create_mcp
from consultation_kb.retrieval.embeddings import (
    DeterministicFakeEmbedder,
    ModelDescriptor,
)


def _offline_embedder(descriptor: ModelDescriptor) -> DeterministicFakeEmbedder:
    unit = np.zeros(descriptor.dimension, dtype=np.float32)
    unit[0] = 1.0
    vocabulary = {
        descriptor.query_prompt: unit,
        descriptor.document_prompt: unit,
    }
    return DeterministicFakeEmbedder(descriptor, vocabulary)


def main() -> None:
    runtime = ProductionRuntime.open(
        embedder_provider=_offline_embedder,
        generation_c1_provider_factory=lambda clock: DeterministicGenerationC1Provider(
            clock=clock
        ),
    )
    try:
        create_mcp(services=runtime.handler_services).run("stdio")
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
