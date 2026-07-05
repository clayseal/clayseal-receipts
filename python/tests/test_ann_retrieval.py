from __future__ import annotations

from agentauth.capabilities.scoping.retrieval.ann import CosineAnnIndex, HashingEmbedder


def test_numpy_ann_index_ranks_shared_tokens() -> None:
    embedder = HashingEmbedder(dim=64)
    index = CosineAnnIndex.from_texts(
        chunk_ids=["a", "b", "c"],
        texts=[
            "alpha beta gamma",
            "delta epsilon zeta",
            "alpha omega",
        ],
        embedder=embedder,
    )
    hits = index.top_n("alpha", 2, embedder=embedder)
    assert hits
    assert hits[0].chunk_id in {"a", "c"}
    assert hits[0].score >= hits[-1].score
