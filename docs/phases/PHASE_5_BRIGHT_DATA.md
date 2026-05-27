# Phase 5: Bright Data Threat Intelligence Integration

**Status:** Planned (ready to implement)
**Estimated effort:** 15–22 hours

## Quick Summary

Phase 5 adds **live threat intelligence** from Bright Data APIs to ShieldPrompt, replacing static regex patterns with dynamic, continuously-updated threat signatures.

Capabilities this unlocks:
- Real-time detection of zero-day injection techniques
- LLM-powered semantic analysis (Tier 2) backed by live patterns
- Vector-based pattern similarity search
- Dashboard visibility into threat feed updates

## Files to Create / Modify

### New Files (~1000 lines)

| File | Lines | Purpose |
|------|-------|---------|
| core/bright_data_client.py | ~250 | Bright Data API wrapper |
| core/pattern_ingester.py | ~300 | Parse CVE/GitHub/blogs into patterns |
| core/vector_store.py | ~200 | Embeddings + similarity search |
| src/dashboard/threat_intelligence.py | ~250 | Threat feed UI tab |

### Modified Files (~130 lines added)

| File | Lines Added | Change |
|------|-------------|--------|
| core/threat_intel.py | +300 | Implement 7 skeleton methods |
| core/shield.py | +100 | Enhance Tier 2 semantic analysis |
| src/dashboard/app.py | +30 | Add threat intel tab |

## Implementation Sequence

1. Bright Data Client — test in isolation
2. Pattern Ingester — mock Bright Data responses
3. Vector Store — FAISS local, no extra infrastructure
4. Enhanced threat_intel.py — orchestration layer
5. Tier 2 Semantic Analysis — integrate LLM + vectors
6. Dashboard UI — final polish
7. Testing & validation

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Vector Store | FAISS | Local, fast, no extra infra |
| Embedding Model | text-embedding-3-small | Cost-effective |
| Update Schedule | Hourly | Configurable via env var |
| Rate Limiting | 100 req/min | Tunable |
| Pattern Retention | 90 days | Balances history vs. storage |

## New Dependencies

```
faiss-cpu==1.7.4
openai==1.3.9
aiohttp==3.9.0
```

## Environment Variables

```bash
BRIGHT_DATA_API_KEY=
BRIGHT_DATA_USERNAME=
BRIGHT_DATA_PASSWORD=
VECTOR_STORE_TYPE=faiss
VECTOR_STORE_PATH=./data/vector_store/
EMBEDDING_MODEL=text-embedding-3-small
THREAT_INTEL_UPDATE_INTERVAL=3600
ENABLE_TIER2_SEMANTIC=true
ENABLE_VECTOR_SEARCH=true
ENABLE_LIVE_SCRAPING=true
```

## Success Criteria

- [ ] Bright Data API integration working
- [ ] Dynamic patterns updated within 5 min of scrape
- [ ] Vector search returns relevant patterns (> 0.7 relevance)
- [ ] Tier 2 detection improves false negatives by ≥ 10%
- [ ] Dashboard threat intel tab functional
- [ ] All existing tests passing (116+ tests)

## Verification Strategy

- Unit tests per component (mocked Bright Data)
- Integration tests for full pipeline
- Acceptance tests with dashboard
- Performance benchmarks (vector search < 50ms)
- Regression tests on Tier 1 accuracy

## Notes

- Phase 4 (dashboard) is production-ready — no breaking changes expected
- Tier 1 (regex) is fully implemented and fast (~5-10ms)
- Phase 5 enhances Tier 2/3 slots only — Tier 1 unchanged
- Bright Data SDK already present in requirements.txt
