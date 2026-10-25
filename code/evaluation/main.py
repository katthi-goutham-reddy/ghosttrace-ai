"""
GhostTrace AI — Evaluation Harness

Computes case-level, step-level, field-level, and sequence accuracy metrics
for deletion audit predictions against public samples and custom test suites.
"""
import sys
import json
import csv
from pathlib import Path
from typing import Dict, List, Tuple, Any

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.config import Config
from code.audit_pipeline import AuditPipeline


def evaluate_predictions(gold_map: Dict[str, Tuple[str, List[Dict[str, Any]]]],
                         pred_map: Dict[str, Tuple[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
    """
    Evaluates predictions against gold answers across multiple accuracy dimensions:
    - Case-level deletion_status accuracy
    - Step-level set precision, recall, and F1
    - Field-level accuracy (system_id, resource_id, operation, state, evidence_id)
    - Phase & step sequence ordering accuracy
    """
    total_cases = len(gold_map)
    status_matches = 0
    exact_sequence_matches = 0

    total_gold_steps = 0
    total_pred_steps = 0
    matched_steps = 0

    field_evals = {
        "phase": {"correct": 0, "total": 0},
        "system_id": {"correct": 0, "total": 0},
        "resource_id": {"correct": 0, "total": 0},
        "operation": {"correct": 0, "total": 0},
        "state": {"correct": 0, "total": 0},
        "evidence_id": {"correct": 0, "total": 0},
    }

    sequence_valid_count = 0

    for cid, (gold_status, gold_steps) in gold_map.items():
        if cid not in pred_map:
            continue
        pred_status, pred_steps = pred_map[cid]

        # Case-level status
        if pred_status == gold_status:
            status_matches += 1

        # Check sequence compliance
        phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        is_seq_valid = True
        last_phase = -1
        for idx, s in enumerate(pred_steps):
            if s.get("step_no") != idx + 1:
                is_seq_valid = False
            p_val = phase_order.get(s.get("phase"), -1)
            if p_val < last_phase:
                is_seq_valid = False
            last_phase = p_val
        if is_seq_valid:
            sequence_valid_count += 1

        # Exact match
        if pred_status == gold_status and pred_steps == gold_steps:
            exact_sequence_matches += 1

        total_gold_steps += len(gold_steps)
        total_pred_steps += len(pred_steps)

        # Compare step by step where alignment matches
        for s_idx in range(min(len(gold_steps), len(pred_steps))):
            g_step = gold_steps[s_idx]
            p_step = pred_steps[s_idx]
            for f in field_evals:
                field_evals[f]["total"] += 1
                if p_step.get(f) == g_step.get(f):
                    field_evals[f]["correct"] += 1

        # Set-level step matching
        gold_set = {(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"]) for s in gold_steps}
        pred_set = {(s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"]) for s in pred_steps}
        matched_steps += len(gold_set.intersection(pred_set))

    precision = matched_steps / max(1, total_pred_steps)
    recall = matched_steps / max(1, total_gold_steps)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)

    return {
        "total_cases": total_cases,
        "status_accuracy": status_matches / max(1, total_cases),
        "status_matches": status_matches,
        "exact_sequence_accuracy": exact_sequence_matches / max(1, total_cases),
        "exact_sequence_matches": exact_sequence_matches,
        "sequence_valid_rate": sequence_valid_count / max(1, total_cases),
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "field_accuracies": {
            f: field_evals[f]["correct"] / max(1, field_evals[f]["total"])
            for f in field_evals
        }
    }


def main():
    print("=" * 70)
    print("GhostTrace AI — Evaluation Benchmark")
    print("=" * 70)

    # 1. Load public sample ground truth
    with open(Config.SAMPLE_OUTPUT_PATH, encoding="utf-8") as f:
        gold_map = {
            r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(f)
        }

    # 2. Run pipeline on sample deletion requests
    pipeline = AuditPipeline()
    pred_map = {}
    with open(Config.SAMPLE_DELETION_REQUESTS_PATH, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["case_id"]
            stat, steps = pipeline.audit_case(
                case_id=cid,
                email=r["email"],
                requested_at=r["requested_at"],
                reported_status=r.get("reported_status", ""),
                reported_at=r.get("reported_at", ""),
                audit_at=r["audit_at"],
                request_text=r.get("request_text", "")
            )
            pred_map[cid] = (stat, steps)

    metrics = evaluate_predictions(gold_map, pred_map)

    print(f"Total Evaluated Cases:   {metrics['total_cases']}")
    print(f"Deletion Status Acc:     {metrics['status_accuracy'] * 100:.2f}% ({metrics['status_matches']}/{metrics['total_cases']})")
    print(f"Sequence Valid Rate:     {metrics['sequence_valid_rate'] * 100:.2f}%")
    print(f"Exact Sequence Acc:      {metrics['exact_sequence_accuracy'] * 100:.2f}% ({metrics['exact_sequence_matches']}/{metrics['total_cases']})")
    print(f"Step Precision:          {metrics['step_precision'] * 100:.2f}%")
    print(f"Step Recall:             {metrics['step_recall'] * 100:.2f}%")
    print(f"Step F1 Score:           {metrics['step_f1'] * 100:.2f}%")
    print("\nField-Level Accuracies:")
    for f, acc in metrics["field_accuracies"].items():
        print(f"  - {f:<15}: {acc * 100:.2f}%")
    print("=" * 70)


if __name__ == "__main__":
    main()
