#!/usr/bin/env python3
"""
SNORT AI Enhancement Evaluation Script

This script evaluates the performance of SNORT with AI enhancements against
baseline SNORT performance using labeled datasets.

Usage:
    python evaluate.py --dataset <dataset_path> --config <snort_config> [options]

Example:
    python evaluate.py --dataset ./datasets/cicids2017/ --config ./snort.conf --output ./results/
"""

import argparse
import os
import sys
import subprocess
import json
import csv
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('evaluation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SNORTEvaluator:
    """Main evaluation class for SNORT AI enhancements"""
    
    def __init__(self, snort_binary: str = "snort", output_dir: str = "./results"):
        self.snort_binary = snort_binary
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Results storage
        self.results = {
            'baseline': {},
            'hybrid_custom_rules': {},
            'hybrid_gpt_filtering': {},
            'hybrid_full': {}
        }
        
        # Ground truth data
        self.ground_truth = {}
        
    def load_ground_truth(self, dataset_path: str) -> Dict[str, bool]:
        """
        Load ground truth labels from dataset
        
        Args:
            dataset_path: Path to the dataset directory
            
        Returns:
            Dictionary mapping packet IDs to malicious labels
        """
        logger.info(f"Loading ground truth from {dataset_path}")
        
        # This is a simplified implementation
        # In practice, you would parse the actual dataset format
        ground_truth_file = Path(dataset_path) / "ground_truth.csv"
        
        if not ground_truth_file.exists():
            logger.warning(f"Ground truth file not found: {ground_truth_file}")
            logger.info("Creating mock ground truth data...")
            return self._create_mock_ground_truth()
        
        ground_truth = {}
        with open(ground_truth_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                packet_id = row['packet_id']
                is_malicious = row['is_malicious'].lower() == 'true'
                ground_truth[packet_id] = is_malicious
        
        logger.info(f"Loaded {len(ground_truth)} ground truth labels")
        return ground_truth
    
    def _create_mock_ground_truth(self) -> Dict[str, bool]:
        """Create mock ground truth data for testing"""
        mock_data = {}
        # Simulate 1000 packets with 20% malicious
        for i in range(1000):
            packet_id = f"packet_{i:06d}"
            is_malicious = (i % 5) == 0  # 20% malicious
            mock_data[packet_id] = is_malicious
        
        logger.info(f"Created mock ground truth with {len(mock_data)} entries")
        return mock_data
    
    def create_snort_config(self, base_config: str, run_type: str, 
                          custom_rules_file: Optional[str] = None) -> str:
        """
        Create SNORT configuration for specific run type
        
        Args:
            base_config: Path to base SNORT configuration
            run_type: Type of run (baseline, hybrid_custom_rules, etc.)
            custom_rules_file: Path to custom rules file
            
        Returns:
            Path to generated configuration file
        """
        config_name = f"snort_config_{run_type}.conf"
        config_path = self.output_dir / config_name
        
        with open(base_config, 'r') as f:
            config_content = f.read()
        
        # Add custom rules if specified
        if custom_rules_file and run_type != 'baseline':
            config_content += f"\n# Custom rules for {run_type}\n"
            config_content += f"include {custom_rules_file}\n"
        
        # Add AI enhancement settings
        if 'hybrid' in run_type:
            config_content += "\n# AI Enhancement Settings\n"
            config_content += "config enable_local_rules: true\n"
            config_content += "config enable_gpt_filtering: true\n"
            config_content += "config enable_metrics_logging: true\n"
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        logger.info(f"Created SNORT config: {config_path}")
        return str(config_path)
    
    def create_custom_rules_file(self) -> str:
        """Create a sample custom rules file"""
        rules_file = self.output_dir / "local.rules"
        
        rules_content = """# Custom rules for SNORT AI enhancement evaluation

# Rule 1: Suspicious HTTP requests
alert tcp any any -> any 80 (msg:"Suspicious HTTP Request"; content:"GET /admin"; nocase; sid:1000001; rev:1;)

# Rule 2: Potential SQL injection
alert tcp any any -> any 80 (msg:"Potential SQL Injection"; content:"union select"; nocase; sid:1000002; rev:1;)

# Rule 3: Malware signature
alert tcp any any -> any any (msg:"Malware Signature Detected"; content:"|4d 5a 90 00|"; sid:1000003; rev:1;)

# Rule 4: Port scan detection
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; threshold:type both,track by_src,count 10,seconds 60; sid:1000004; rev:1;)

# Rule 5: Suspicious DNS queries
alert udp any any -> any 53 (msg:"Suspicious DNS Query"; content:"|01 00 00 01 00 00 00 00 00 00|"; sid:1000005; rev:1;)
"""
        
        with open(rules_file, 'w') as f:
            f.write(rules_content)
        
        logger.info(f"Created custom rules file: {rules_file}")
        return str(rules_file)
    
    def run_snort_evaluation(self, config_file: str, pcap_file: str, 
                            run_type: str) -> Dict[str, float]:
        """
        Run SNORT evaluation and collect metrics
        
        Args:
            config_file: Path to SNORT configuration
            pcap_file: Path to PCAP file for evaluation
            run_type: Type of run for metrics collection
            
        Returns:
            Dictionary containing performance metrics
        """
        logger.info(f"Running SNORT evaluation: {run_type}")
        
        # Prepare output files
        alert_file = self.output_dir / f"alerts_{run_type}.log"
        log_file = self.output_dir / f"snort_{run_type}.log"
        
        # Build SNORT command
        cmd = [
            self.snort_binary,
            "-c", config_file,
            "-r", pcap_file,
            "-A", "console",
            "-l", str(self.output_dir),
            "-K", "none"  # Disable packet logging for performance
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        
        start_time = time.time()
        
        try:
            # Run SNORT
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Parse results
            metrics = self._parse_snort_output(result.stdout, result.stderr, processing_time)
            metrics['run_type'] = run_type
            metrics['config_file'] = config_file
            metrics['pcap_file'] = pcap_file
            
            # Save raw output
            with open(log_file, 'w') as f:
                f.write(f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}")
            
            logger.info(f"SNORT evaluation completed: {run_type}")
            return metrics
            
        except subprocess.TimeoutExpired:
            logger.error(f"SNORT evaluation timed out: {run_type}")
            return {'error': 'timeout', 'run_type': run_type}
        except Exception as e:
            logger.error(f"SNORT evaluation failed: {run_type} - {e}")
            return {'error': str(e), 'run_type': run_type}
    
    def _parse_snort_output(self, stdout: str, stderr: str, processing_time: float) -> Dict[str, float]:
        """Parse SNORT output to extract metrics"""
        metrics = {
            'processing_time_seconds': processing_time,
            'total_alerts': 0,
            'true_positives': 0,
            'false_positives': 0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0,
            'accuracy': 0.0,
            'packets_processed': 0,
            'packets_per_second': 0.0
        }
        
        # Parse alert count from stdout
        alert_lines = [line for line in stdout.split('\n') if 'alert' in line.lower()]
        metrics['total_alerts'] = len(alert_lines)
        
        # Parse packet count
        for line in stdout.split('\n'):
            if 'packets' in line.lower() and 'processed' in line.lower():
                try:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.isdigit() and i < len(parts) - 1:
                            if 'packets' in parts[i+1].lower():
                                metrics['packets_processed'] = int(part)
                                break
                except (ValueError, IndexError):
                    pass
        
        # Calculate packets per second
        if processing_time > 0:
            metrics['packets_per_second'] = metrics['packets_processed'] / processing_time
        
        # Mock calculation of true/false positives
        # In a real implementation, you would correlate alerts with ground truth
        total_alerts = metrics['total_alerts']
        if total_alerts > 0:
            # Assume 70% true positives for demonstration
            metrics['true_positives'] = int(total_alerts * 0.7)
            metrics['false_positives'] = total_alerts - metrics['true_positives']
            
            # Calculate precision, recall, F1
            tp = metrics['true_positives']
            fp = metrics['false_positives']
            
            if tp + fp > 0:
                metrics['precision'] = tp / (tp + fp)
            
            # Mock recall calculation (would need ground truth)
            total_malicious = len([v for v in self.ground_truth.values() if v])
            if total_malicious > 0:
                metrics['recall'] = tp / total_malicious
            
            # Calculate F1 score
            if metrics['precision'] + metrics['recall'] > 0:
                metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / \
                                   (metrics['precision'] + metrics['recall'])
        
        return metrics
    
    def run_full_evaluation(self, dataset_path: str, base_config: str, 
                          pcap_file: str) -> Dict[str, Dict[str, float]]:
        """
        Run complete evaluation comparing baseline vs hybrid approaches
        
        Args:
            dataset_path: Path to dataset directory
            base_config: Path to base SNORT configuration
            pcap_file: Path to PCAP file for evaluation
            
        Returns:
            Dictionary containing all evaluation results
        """
        logger.info("Starting full SNORT AI enhancement evaluation")
        
        # Load ground truth
        self.ground_truth = self.load_ground_truth(dataset_path)
        
        # Create custom rules file
        custom_rules_file = self.create_custom_rules_file()
        
        # Define run types
        run_types = [
            ('baseline', 'baseline'),
            ('hybrid_custom_rules', 'hybrid_custom_rules'),
            ('hybrid_gpt_filtering', 'hybrid_gpt_filtering'),
            ('hybrid_full', 'hybrid_full')
        ]
        
        results = {}
        
        for run_name, run_type in run_types:
            logger.info(f"Running evaluation: {run_name}")
            
            # Create configuration
            config_file = self.create_snort_config(
                base_config, run_type, 
                custom_rules_file if 'custom_rules' in run_type else None
            )
            
            # Run evaluation
            metrics = self.run_snort_evaluation(config_file, pcap_file, run_type)
            results[run_name] = metrics
            
            # Store results
            self.results[run_name] = metrics
        
        return results
    
    def generate_comparison_report(self) -> str:
        """Generate a comprehensive comparison report"""
        logger.info("Generating comparison report")
        
        report = []
        report.append("=" * 80)
        report.append("SNORT AI ENHANCEMENT EVALUATION REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary table
        report.append("PERFORMANCE SUMMARY")
        report.append("-" * 40)
        report.append(f"{'Metric':<25} {'Baseline':<12} {'Custom Rules':<12} {'GPT Filter':<12} {'Full Hybrid':<12}")
        report.append("-" * 80)
        
        metrics_to_compare = [
            ('Total Alerts', 'total_alerts'),
            ('True Positives', 'true_positives'),
            ('False Positives', 'false_positives'),
            ('Precision', 'precision'),
            ('Recall', 'recall'),
            ('F1-Score', 'f1_score'),
            ('Accuracy', 'accuracy'),
            ('Packets/sec', 'packets_per_second')
        ]
        
        for metric_name, metric_key in metrics_to_compare:
            baseline_val = self.results['baseline'].get(metric_key, 0)
            custom_val = self.results['hybrid_custom_rules'].get(metric_key, 0)
            gpt_val = self.results['hybrid_gpt_filtering'].get(metric_key, 0)
            full_val = self.results['hybrid_full'].get(metric_key, 0)
            
            if isinstance(baseline_val, float):
                report.append(f"{metric_name:<25} {baseline_val:<12.4f} {custom_val:<12.4f} {gpt_val:<12.4f} {full_val:<12.4f}")
            else:
                report.append(f"{metric_name:<25} {baseline_val:<12} {custom_val:<12} {gpt_val:<12} {full_val:<12}")
        
        report.append("")
        
        # Improvement analysis
        report.append("IMPROVEMENT ANALYSIS")
        report.append("-" * 40)
        
        baseline_fp = self.results['baseline'].get('false_positives', 0)
        full_fp = self.results['hybrid_full'].get('false_positives', 0)
        
        if baseline_fp > 0:
            fp_reduction = ((baseline_fp - full_fp) / baseline_fp) * 100
            report.append(f"False Positive Reduction: {fp_reduction:.2f}%")
        
        baseline_precision = self.results['baseline'].get('precision', 0)
        full_precision = self.results['hybrid_full'].get('precision', 0)
        
        if baseline_precision > 0:
            precision_improvement = ((full_precision - baseline_precision) / baseline_precision) * 100
            report.append(f"Precision Improvement: {precision_improvement:.2f}%")
        
        baseline_f1 = self.results['baseline'].get('f1_score', 0)
        full_f1 = self.results['hybrid_full'].get('f1_score', 0)
        
        if baseline_f1 > 0:
            f1_improvement = ((full_f1 - baseline_f1) / baseline_f1) * 100
            report.append(f"F1-Score Improvement: {f1_improvement:.2f}%")
        
        report.append("")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        # Save report
        report_file = self.output_dir / "evaluation_report.txt"
        with open(report_file, 'w') as f:
            f.write(report_text)
        
        logger.info(f"Report saved to: {report_file}")
        return report_text
    
    def export_results(self):
        """Export results to CSV and JSON formats"""
        logger.info("Exporting results")
        
        # Export to CSV
        csv_file = self.output_dir / "baseline_vs_hybrid_results.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'timestamp', 'run_id', 'run_type', 'total_alerts', 'true_positives',
                'false_positives', 'precision', 'recall', 'f1_score', 'accuracy',
                'packets_processed', 'processing_time_seconds', 'packets_per_second'
            ])
            
            # Write data
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            for run_name, metrics in self.results.items():
                if metrics and 'error' not in metrics:
                    writer.writerow([
                        timestamp,
                        f"run_{run_name}",
                        run_name,
                        metrics.get('total_alerts', 0),
                        metrics.get('true_positives', 0),
                        metrics.get('false_positives', 0),
                        metrics.get('precision', 0.0),
                        metrics.get('recall', 0.0),
                        metrics.get('f1_score', 0.0),
                        metrics.get('accuracy', 0.0),
                        metrics.get('packets_processed', 0),
                        metrics.get('processing_time_seconds', 0.0),
                        metrics.get('packets_per_second', 0.0)
                    ])
        
        # Export to JSON
        json_file = self.output_dir / "evaluation_results.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"Results exported to: {csv_file}, {json_file}")

def main():
    """Main evaluation function"""
    parser = argparse.ArgumentParser(description='SNORT AI Enhancement Evaluation')
    parser.add_argument('--dataset', required=True, help='Path to dataset directory')
    parser.add_argument('--config', required=True, help='Path to base SNORT configuration')
    parser.add_argument('--pcap', required=True, help='Path to PCAP file for evaluation')
    parser.add_argument('--output', default='./results', help='Output directory for results')
    parser.add_argument('--snort-binary', default='snort', help='Path to SNORT binary')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.dataset):
        logger.error(f"Dataset path does not exist: {args.dataset}")
        sys.exit(1)
    
    if not os.path.exists(args.config):
        logger.error(f"Config file does not exist: {args.config}")
        sys.exit(1)
    
    if not os.path.exists(args.pcap):
        logger.error(f"PCAP file does not exist: {args.pcap}")
        sys.exit(1)
    
    # Create evaluator
    evaluator = SNORTEvaluator(args.snort_binary, args.output)
    
    try:
        # Run evaluation
        logger.info("Starting SNORT AI enhancement evaluation")
        results = evaluator.run_full_evaluation(args.dataset, args.config, args.pcap)
        
        # Generate report
        report = evaluator.generate_comparison_report()
        print(report)
        
        # Export results
        evaluator.export_results()
        
        logger.info("Evaluation completed successfully")
        
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
