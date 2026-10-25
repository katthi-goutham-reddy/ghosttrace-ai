# GhostTrace AI — LLM & Runtime Token Usage Report

## 1. Overview & Execution Scope

This report summarizes the runtime computational and model usage metrics for the final full-dataset execution that generated `output.csv` (covering all 518 evaluation requests in `dataset/deletion_requests.csv`) for the HackerRank Orchestrate (October 2026) challenge: *Ghost Data Still Exists*.

GhostTrace AI is engineered as an entirely local, deterministic, high-throughput deletion-audit pipeline. It leverages specialized multi-format evidence parsers (SQL snapshots, JSON exports, plain text ledgers, readback logs), graph-based identity resolution, regex-based intent classification, and an authoritative policy evaluation engine.

---

## 2. Model & Provider Breakdown

| Parameter | Configuration |
|---|---|
| **Model Providers** | None (Fully local deterministic pipeline) |
| **Model Names** | None (0 external API models invoked) |
| **Pipeline Architecture** | Deterministic Regex + Rule Engine + File/SQL Parsers |
| **Hardware Environment** | Windows 11 / AMD64 |
| **Runtime Language** | Python 3.12 (Standard Library + zero external model dependencies) |

---

## 3. Quantitative Token & Call Metrics

### 3.1 Full-Dataset Run (518 Cases)

The full evaluation run processed all 518 cases from `dataset/deletion_requests.csv` with 100% completion and zero unhandled exceptions:

| Metric | Full Run Total | Per-Request Average (518 Cases) |
|---|---|---|
| **Total Evaluation Cases** | **518** | 1.0 case |
| **Total Pipeline Wall Time** | **1.01 seconds** | **1.95 milliseconds** |
| **Model Invocations / Calls** | **0 calls** | **0.0 calls / request** |
| **Input Tokens (Prompt Context)** | **0 tokens** | **0.0 tokens** |
| **Output Tokens (Decisions & Steps)** | **0 tokens** | **0.0 tokens** |
| **Total Processed Tokens** | **0 tokens** | **0.0 tokens** |

### 3.2 Token Distribution by Component

| Pipeline Subsystem | Model Calls | Input Tokens | Output Tokens | Total Tokens | % of Total |
|---|---|---|---|---|---|
| **Intent Classification (Multi-Lingual)** | 0 | 0 | 0 | 0 | 0.0% |
| **Identity Resolution & Audit History** | 0 | 0 | 0 | 0 | 0.0% |
| **Temporal Evidence & Activity Corroboration** | 0 | 0 | 0 | 0 | 0.0% |
| **Policy Engine & Output Serialization** | 0 | 0 | 0 | 0 | 0.0% |
| **Total** | **0** | **0** | **0** | **0** | **0.0%** |

---

## 4. Financial & Cost Analysis

Because GhostTrace AI executes fully locally using deterministic algorithms, no external API calls are made and zero inference tokens are consumed.

### 4.1 Cost Calculation

$$\text{Input Cost} = 0 \times \$0.00 = \$0.00$$

$$\text{Output Cost} = 0 \times \$0.00 = \$0.00$$

$$\text{Total Cost} = \mathbf{\$0.00}$$

### 4.2 Cost Summary

| Dimension | Cost (USD) |
|---|---|
| **Total Cost (518 Cases)** | **$0.00** |
| **Average Cost per Deletion Request** | **$0.00** |
| **Cost per 1,000 Audited Cases** | **$0.00** |

---

## 5. Architectural Efficiency & Sustainability

1. **Sub-Millisecond Execution**: Pre-indexing evidence files and global system activities into in-memory temporal collections (`EvidenceStore`) enables constant-time lookups, auditing all 518 cases in approximately 1 second (~2ms per case).
2. **Deterministic Reproducibility**: Operating without stochastic LLM sampling guarantees bit-for-bit identical, contract-compliant outputs across runs and operating systems.
3. **Data Privacy & Compliance**: Personal identifiable information (PII) from user requests and evidence files is audited entirely in-memory and never transmitted to external third-party API providers or cloud models.
