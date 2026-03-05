import json
import subprocess
import os
import csv
from typing import List, Dict

# Assumes analyzer-cli.jar is built and located in the analyzer/target/ directory
ANALYZER_JAR = "../analyzer/target/analyzer-cli-1.0-SNAPSHOT-jar-with-dependencies.jar"

# A mock ground truth structure for evaluation purposes.
# In a real conference paper, this would be loaded from a human-annotated dataset.
# Format: { "repo_name": [ {"file": "...", "line": 10}, ... ] }
GROUND_TRUTH = {
    "test-repo-1": [
        {"filePath": "VulnerableClass.java", "lineNumber": 42},
        {"filePath": "KeyExchangeController.java", "lineNumber": 15}
    ]
}

def run_analyzer(repo_path: str, use_baseline: bool) -> List[Dict]:
    cmd = ["java", "-jar", ANALYZER_JAR, "--repoPath", repo_path]
    if use_baseline:
        cmd.append("--baseline")
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Parse the JSON output from stdout
        response = json.loads(result.stdout)
        return response.get("findings", [])
    except subprocess.CalledProcessError as e:
        print(f"Error running analyzer on {repo_path}: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output for {repo_path}: {e}")
        return []

def compute_metrics(predictions: List[Dict], ground_truth: List[Dict]):
    """
    Computes Precision, Recall, and Ranking Difference.
    """
    # A true positive is a prediction that matches the ground truth file and line
    tp_count = 0
    
    # To compute ranking difference, we compare the top-k risky findings.
    # We sort predictions by riskScore descending.
    sorted_preds = sorted(predictions, key=lambda x: x.get("riskScore", 0), reverse=True)
    
    gt_set = set(f"{gt['filePath']}:{gt['lineNumber']}" for gt in ground_truth)
    pred_set = set(f"{os.path.basename(p['filePath'])}:{p['lineNumber']}" for p in predictions)
    
    # Naive matching (in reality, requires exact path resolution)
    for p in predictions:
        match_key = f"{os.path.basename(p['filePath'])}:{p['lineNumber']}"
        if match_key in gt_set:
            tp_count += 1
            
    fp_count = len(predictions) - tp_count
    fn_count = len(ground_truth) - tp_count
    
    precision = tp_count / len(predictions) if predictions else 0.0
    recall = tp_count / len(ground_truth) if ground_truth else 0.0
    
    # Ranking difference: Average position of True Positives in the sorted results
    ranking_diff = 0.0
    tp_ranks = []
    for rank, p in enumerate(sorted_preds, 1):
        match_key = f"{os.path.basename(p['filePath'])}:{p['lineNumber']}"
        if match_key in gt_set:
            tp_ranks.append(rank)
            
    if tp_ranks:
        ranking_diff = sum(tp_ranks) / len(tp_ranks)
        
    return precision, recall, ranking_diff

def export_csv(results: List[Dict], output_file: str):
    if not results:
        print("No results to export.")
        return
        
    keys = results[0].keys()
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

def main():
    if not os.path.exists(ANALYZER_JAR):
        print(f"JAR not found at {ANALYZER_JAR}. Please build the analyzer first using 'mvn clean package'.")
        return

    # In a real scenario, repo_paths would be dynamically loaded
    # For demonstration, we assume a structured directory of evaluation repos
    evaluation_repos = ["../sandbox/test-repo-1"] 
    
    final_results = []
    
    for repo in evaluation_repos:
        repo_name = os.path.basename(repo)
        
        # We skip actual execution if the test-repo doesn't exist to prevent crash during setup phase
        if not os.path.exists(repo):
            print(f"Skipping {repo_name} - Directory not found.")
            continue
            
        truth = GROUND_TRUTH.get(repo_name, [])
        
        # 1. Run Pipeline
        print(f"Running AST Pipeline on {repo_name}...")
        pipeline_findings = run_analyzer(repo, use_baseline=False)
        p_prec, p_rec, p_rank = compute_metrics(pipeline_findings, truth)
        
        # 2. Run Baseline
        print(f"Running Baseline Scanner on {repo_name}...")
        baseline_findings = run_analyzer(repo, use_baseline=True)
        b_prec, b_rec, b_rank = compute_metrics(baseline_findings, truth)
        
        final_results.append({
            "Repository": repo_name,
            "Mode": "Pipeline",
            "Findings_Count": len(pipeline_findings),
            "Precision": round(p_prec, 3),
            "Recall": round(p_rec, 3),
            "Avg_TP_Rank": round(p_rank, 1)
        })
        
        final_results.append({
            "Repository": repo_name,
            "Mode": "Baseline",
            "Findings_Count": len(baseline_findings),
            "Precision": round(b_prec, 3),
            "Recall": round(b_rec, 3),
            "Avg_TP_Rank": round(b_rank, 1)
        })

    if final_results:
        export_csv(final_results, "evaluation_results.csv")
        print("Evaluation complete. Results exported to evaluation_results.csv")

if __name__ == "__main__":
    main()
