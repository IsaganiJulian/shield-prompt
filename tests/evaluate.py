"""
Evaluation Suite for ShieldPrompt Detection System

Metrics:
  - True Positive Rate (TPR): Correctly identified malicious inputs
  - False Positive Rate (FPR): Benign inputs incorrectly flagged
  - False Negative Rate (FNR): Malicious inputs missed
  - Precision & Recall
  - Detection latency
"""

import logging
import json
import time
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

import sys
import os
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.core.shield import ShieldDetector, ThreatLevel

# Configure local module logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class EvaluationMetrics:
    """Evaluation metrics for detection performance."""
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    tpr: float  # True Positive Rate
    fpr: float  # False Positive Rate
    fnr: float  # False Negative Rate
    precision: float
    recall: float
    f1_score: float
    avg_detection_latency_ms: float


class EvaluationSuite:
    """
    Comprehensive evaluation framework for ShieldPrompt.

    Tests detection accuracy, remediation success, and performance.
    """

    def __init__(self, detector=None, supervisor=None):
        """
        Initialize evaluation suite.
        """
        self.detector = detector or ShieldDetector()
        self.supervisor = supervisor  # Placeholder for SupervisorAgent integration
        logger.info("EvaluationSuite initialized successfully.")

    def load_test_dataset(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Load test dataset (malicious and benign samples) from a JSON file.
        """
        try:
            with open(filepath, "r") as f:
                dataset = json.load(f)
            logger.info(f"Successfully loaded {len(dataset)} test cases from {filepath}")
            return dataset
        except Exception as e:
            logger.error(f"Failed to load test dataset at {filepath}: {str(e)}")
            return []

    def evaluate_detection_accuracy(self, test_dataset: List[Dict[str, Any]]) -> EvaluationMetrics:
        """
        Evaluate detection accuracy across test dataset.
        Calculates TP, TN, FP, FN and computes mathematical metrics.
        """
        tp, tn, fp, fn = 0, 0, 0, 0
        total_latency_ms = 0.0
        
        for case in test_dataset:
            user_input = case["input"]
            # Detect ground truth label
            is_actually_malicious = (case["label"] == "malicious")
            
            # Benchmark detection execution time
            start_time = time.perf_counter()
            result = self.detector.detect(user_input)
            end_time = time.perf_counter()
            
            total_latency_ms += (end_time - start_time) * 1000.0
            
            # ShieldPrompt blocks if threat level is anything other than CLEAN
            predicted_malicious = (result.threat_level != ThreatLevel.CLEAN)
            
            # Populate confusion matrix quadrants
            if is_actually_malicious and predicted_malicious:
                tp += 1
            elif not is_actually_malicious and not predicted_malicious:
                tn += 1
            elif not is_actually_malicious and predicted_malicious:
                fp += 1
            elif is_actually_malicious and not predicted_malicious:
                fn += 1

        # Compute Rates (Protect against zero-division errors)
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tpr
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        avg_latency = total_latency_ms / len(test_dataset) if test_dataset else 0.0

        return EvaluationMetrics(
            true_positives=tp, true_negatives=tn, false_positives=fp, false_negatives=fn,
            tpr=tpr, fpr=fpr, fnr=fnr, precision=precision, recall=recall, f1_score=f1_score,
            avg_detection_latency_ms=avg_latency
        )

    def generate_confusion_matrix(self, test_dataset: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Generate confusion matrix for visualization counters.
        """
        metrics = self.evaluate_detection_accuracy(test_dataset)
        return {
            "True Positives (TP)": metrics.true_positives,
            "True Negatives (TN)": metrics.true_negatives,
            "False Positives (FP)": metrics.false_positives,
            "False Negatives (FN)": metrics.false_negatives
        }

    def report(self, test_dataset: List[Dict[str, Any]]) -> str:
        """
        Generate comprehensive text evaluation report.
        """
        metrics = self.evaluate_detection_accuracy(test_dataset)
        
        report_str = (
            f"==================================================\n"
            f"          SHIELDPROMPT SECURITY AUDIT REPORT      \n"
            f"==================================================\n"
            f"Total Samples Evaluated : {len(test_dataset)}\n"
            f"Average System Latency  : {metrics.avg_detection_latency_ms:.3f} ms\n\n"
            f"--- Confusion Matrix Quadrants ---\n"
            f"  True Positives (TP)  : {metrics.true_positives}  [Correctly Blocked]\n"
            f"  True Negatives (TN)  : {metrics.true_negatives}  [Correctly Allowed]\n"
            f"  False Positives (FP) : {metrics.false_positives}  [Safe Input Blocked]\n"
            f"  False Negatives (FN) : {metrics.false_negatives}  [Exploits Missed]\n\n"
            f"--- Security Performance KPIs ---\n"
            f"  True Positive Rate (Recall) : {metrics.tpr * 100:.1f}%\n"
            f"  False Positive Rate (FPR)   : {metrics.fpr * 100:.1f}%\n"
            f"  False Negative Rate (FNR)   : {metrics.fnr * 100:.1f}%\n"
            f"  Precision Score             : {metrics.precision * 100:.1f}%\n"
            f"  F1-Score Balance Metric     : {metrics.f1_score * 100:.1f}%\n"
            f"=================================================="
        )
        return report_str


def run_evaluation(detector, supervisor, dataset_path: str) -> EvaluationMetrics:
    """
    Run full evaluation pipeline orchestrator.
    """
    suite = EvaluationSuite(detector=detector, supervisor=supervisor)
    dataset = suite.load_test_dataset(dataset_path)
    
    if not dataset:
        print("Error: Evaluation aborted. Dataset empty or missing.")
        return None
        
    print(suite.report(dataset))
    return suite.evaluate_detection_accuracy(dataset)


if __name__ == "__main__":
    # Path configuration for default dataset location
    default_path = "tests/eval_dataset.json"
    
    # Initialize components
    detector_instance = ShieldDetector()
    supervisor_instance = None  # To be connected when supervisor script is done
    
    print("\n--- Initializing Automated ShieldPrompt Testing Pipeline ---\n")
    run_evaluation(detector_instance, supervisor_instance, default_path)
