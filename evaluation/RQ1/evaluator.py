"""
Main evaluation framework for Android Framework Methods
"""

import time
import pandas as pd
from typing import Dict, Any
import logging
from datetime import datetime

from llm_interface import LLMInterface
from utils import (
    SimilarityCalculator, load_ground_truth, save_json,
    calculate_method_similarity, count_total_methods,
    get_method_list, create_progress_summary
)
from config import OUTPUT_DIR, PROGRESS_SAVE_INTERVAL, LLM_CONFIGS

logger = logging.getLogger(__name__)

class FrameworkMethodEvaluator:
    """Main class for evaluating LLM performance on framework method understanding"""
    
    def __init__(self, ground_truth_file: str, openai_api_key: str = None):
        self.ground_truth = load_ground_truth(ground_truth_file)
        self.llm_interface = LLMInterface(openai_api_key)
        self.similarity_calc = SimilarityCalculator()
        self.results = {}
        self.start_time = None
        
        # Validate ground truth structure
        self._validate_ground_truth()
        
        logger.info(f"Initialized evaluator with {count_total_methods(self.ground_truth)} methods")
    
    def _validate_ground_truth(self):
        """Validate ground truth data structure"""
        if "framework_methods" not in self.ground_truth:
            raise ValueError("Invalid ground truth format: missing 'framework_methods'")
        
        total_methods = count_total_methods(self.ground_truth)
        if total_methods == 0:
            raise ValueError("No methods found in ground truth")
        
        logger.info(f"Ground truth validation passed: {total_methods} methods across {len(self.ground_truth['framework_methods'])} categories")
    
    def run_full_evaluation(self, output_dir: str = OUTPUT_DIR, resume_from: str = None):
        """Run complete evaluation of all methods across all LLMs"""
        self.start_time = time.time()
        
        # Load existing results if resuming
        if resume_from:
            try:
                self.results = load_ground_truth(resume_from)
                logger.info(f"Resumed from {resume_from}")
            except Exception as e:
                logger.warning(f"Could not resume from {resume_from}: {e}")
        
        methods_list = get_method_list(self.ground_truth)
        total_methods = len(methods_list)
        total_evaluations = total_methods * len(LLM_CONFIGS)
        
        logger.info(f"Starting evaluation: {total_methods} methods × {len(LLM_CONFIGS)} LLMs = {total_evaluations} evaluations")
        
        for idx, method_info in enumerate(methods_list):
            signature = method_info["signature"]
            category = method_info["category"]
            method_data = method_info["data"]
            
            # Skip if already evaluated
            if signature in self.results:
                logger.info(f"[{idx+1}/{total_methods}] Skipping {signature} (already evaluated)")
                continue
            
            logger.info(f"[{idx+1}/{total_methods}] Evaluating: {signature}")
            
            # Initialize result structure
            self.results[signature] = {
                "category": category,
                "ground_truth": method_data,
                "llm_responses": {},
                "similarities": {},
                "evaluation_timestamp": datetime.now().isoformat()
            }
            
            # Evaluate with each LLM
            for llm_name in LLM_CONFIGS.keys():
                logger.info(f"  → Querying {llm_name}")
                
                try:
                    # Query LLM
                    llm_result = self.llm_interface.evaluate_method(signature, llm_name)
                    self.results[signature]["llm_responses"][llm_name] = llm_result
                    
                    # Calculate similarity if successful
                    if llm_result["success"]:
                        similarity_scores = calculate_method_similarity(
                            method_data, 
                            llm_result["parsed_response"],
                            self.similarity_calc
                        )
                        self.results[signature]["similarities"][llm_name] = similarity_scores
                        
                        # Log similarity score
                        overall_sim = similarity_scores.get("overall_similarity", 0.0)
                        logger.info(f"    → Overall similarity: {overall_sim:.3f}")
                    else:
                        logger.warning(f"    → Failed: {llm_result.get('error', 'Unknown error')}")
                
                except Exception as e:
                    logger.error(f"    → Exception: {e}")
                    self.results[signature]["llm_responses"][llm_name] = {
                        "success": False,
                        "error": str(e),
                        "llm": llm_name
                    }
            
            # Save progress periodically
            if (idx + 1) % PROGRESS_SAVE_INTERVAL == 0:
                self._save_progress(output_dir, idx + 1, total_methods)
        
        # Save final results
        self._save_final_results(output_dir)
        self._generate_excel_report(f"{output_dir}/evaluation_results.xlsx")
        
        # Print summary
        self._print_evaluation_summary()
        
        logger.info(f"Evaluation complete! Results saved to {output_dir}/")
    
    def _save_progress(self, output_dir: str, current_idx: int, total_methods: int):
        """Save progress backup"""
        progress_file = f"{output_dir}/progress_backup.json"
        save_json(self.results, progress_file)
        
        summary = create_progress_summary(self.results, total_methods)
        logger.info(f"Progress saved: {summary['completed_methods']}/{total_methods} methods ({summary['progress_percentage']:.1f}%)")
    
    def _save_final_results(self, output_dir: str):
        """Save final evaluation results"""
        # Full results
        save_json(self.results, f"{output_dir}/full_results.json")
        
        # Summary statistics
        summary = self._generate_summary_stats()
        save_json(summary, f"{output_dir}/summary_statistics.json")
        
        logger.info("Final results saved")
    
    def _generate_summary_stats(self) -> Dict:
        """Generate summary statistics"""
        stats = {
            "evaluation_info": {
                "total_methods": len(self.results),
                "categories": list(set(r["category"] for r in self.results.values())),
                "llms_evaluated": list(LLM_CONFIGS.keys()),
                "evaluation_duration_seconds": time.time() - self.start_time if self.start_time else None
            },
            "success_rates": {},
            "similarity_averages": {},
            "category_performance": {}
        }
        
        # Calculate success rates and similarity averages per LLM
        for llm_name in LLM_CONFIGS.keys():
            successes = 0
            total_sims = []
            
            for result in self.results.values():
                llm_response = result["llm_responses"].get(llm_name, {})
                if llm_response.get("success", False):
                    successes += 1
                    
                    similarity = result["similarities"].get(llm_name, {})
                    if similarity.get("success", False):
                        total_sims.append(similarity["overall_similarity"])
            
            stats["success_rates"][llm_name] = successes / len(self.results)
            stats["similarity_averages"][llm_name] = sum(total_sims) / len(total_sims) if total_sims else 0.0
        
        # Category performance
        for category in stats["evaluation_info"]["categories"]:
            category_results = {sig: res for sig, res in self.results.items() if res["category"] == category}
            
            stats["category_performance"][category] = {}
            for llm_name in LLM_CONFIGS.keys():
                sims = []
                for result in category_results.values():
                    similarity = result["similarities"].get(llm_name, {})
                    if similarity.get("success", False):
                        sims.append(similarity["overall_similarity"])
                
                stats["category_performance"][category][llm_name] = sum(sims) / len(sims) if sims else 0.0
        
        return stats
    
    def _generate_excel_report(self, output_file: str):
        """Generate comprehensive Excel report"""
        try:
            rows = []
            
            for signature, data in self.results.items():
                base_row = {
                    "Category": data["category"],
                    "Method_Signature": signature,
                    "GT_Purpose": data["ground_truth"]["purpose_behavior"],
                    "GT_Return_Type": data["ground_truth"]["return_values"]["type"],
                    "GT_Return_Description": data["ground_truth"]["return_values"]["description"]
                }
                
                # Add LLM responses and similarities
                for llm in LLM_CONFIGS.keys():
                    llm_response = data["llm_responses"].get(llm, {})
                    
                    if llm_response.get("success", False):
                        parsed = llm_response["parsed_response"]
                        base_row[f"{llm}_Purpose"] = parsed.get("purpose_behavior", "N/A")
                        base_row[f"{llm}_Return_Type"] = parsed.get("return_values", {}).get("type", "N/A")
                        base_row[f"{llm}_Return_Description"] = parsed.get("return_values", {}).get("description", "N/A")
                        
                        # Similarity scores
                        similarity = data["similarities"].get(llm, {})
                        if similarity.get("success", False):
                            base_row[f"{llm}_Purpose_Similarity"] = similarity["purpose_similarity"]
                            base_row[f"{llm}_Return_Type_Match"] = similarity["return_type_match"]
                            base_row[f"{llm}_Return_Desc_Similarity"] = similarity["return_desc_similarity"]
                            base_row[f"{llm}_Overall_Similarity"] = similarity["overall_similarity"]
                        else:
                            base_row[f"{llm}_Purpose_Similarity"] = 0.0
                            base_row[f"{llm}_Return_Type_Match"] = False
                            base_row[f"{llm}_Return_Desc_Similarity"] = 0.0
                            base_row[f"{llm}_Overall_Similarity"] = 0.0
                    else:
                        # Mark failed evaluations
                        error_msg = llm_response.get("error", "EVALUATION_FAILED")
                        base_row[f"{llm}_Purpose"] = f"ERROR: {error_msg}"
                        base_row[f"{llm}_Return_Type"] = "ERROR"
                        base_row[f"{llm}_Return_Description"] = "ERROR"
                        base_row[f"{llm}_Purpose_Similarity"] = 0.0
                        base_row[f"{llm}_Return_Type_Match"] = False
                        base_row[f"{llm}_Return_Desc_Similarity"] = 0.0
                        base_row[f"{llm}_Overall_Similarity"] = 0.0
                
                rows.append(base_row)
            
            # Create DataFrame
            df = pd.DataFrame(rows)
            
            # Save to Excel with multiple sheets
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                # Full results
                df.to_excel(writer, sheet_name='Full_Results', index=False)
                
                # Category-wise sheets
                for category in df['Category'].unique():
                    category_df = df[df['Category'] == category]
                    safe_name = category.replace(' ', '_').replace('/', '_')[:31]
                    category_df.to_excel(writer, sheet_name=safe_name, index=False)
                
                # Summary statistics
                summary_stats = self._generate_summary_stats()
                summary_df = pd.DataFrame([
                    {"Metric": "Total Methods", "Value": summary_stats["evaluation_info"]["total_methods"]},
                    {"Metric": "Categories", "Value": len(summary_stats["evaluation_info"]["categories"])},
                    {"Metric": "LLMs", "Value": len(summary_stats["evaluation_info"]["llms_evaluated"])}
                ])
                
                for llm, success_rate in summary_stats["success_rates"].items():
                    summary_df = pd.concat([summary_df, pd.DataFrame([{
                        "Metric": f"{llm}_Success_Rate", 
                        "Value": f"{success_rate:.3f}"
                    }])], ignore_index=True)
                
                for llm, avg_sim in summary_stats["similarity_averages"].items():
                    summary_df = pd.concat([summary_df, pd.DataFrame([{
                        "Metric": f"{llm}_Avg_Similarity", 
                        "Value": f"{avg_sim:.3f}"
                    }])], ignore_index=True)
                
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            logger.info(f"Excel report generated: {output_file}")
            
        except Exception as e:
            logger.error(f"Failed to generate Excel report: {e}")
    
    def _print_evaluation_summary(self):
        """Print evaluation summary to console"""
        summary = self._generate_summary_stats()
        
        print("\n" + "="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Total Methods Evaluated: {summary['evaluation_info']['total_methods']}")
        print(f"Categories: {len(summary['evaluation_info']['categories'])}")
        print(f"LLMs: {len(summary['evaluation_info']['llms_evaluated'])}")
        
        if summary['evaluation_info']['evaluation_duration_seconds']:
            duration = summary['evaluation_info']['evaluation_duration_seconds']
            print(f"Duration: {duration/3600:.1f} hours")
        
        print("\nSUCCESS RATES:")
        for llm, rate in summary['success_rates'].items():
            print(f"  {llm}: {rate:.3f}")
        
        print("\nAVERAGE SIMILARITY SCORES:")
        for llm, score in summary['similarity_averages'].items():
            print(f"  {llm}: {score:.3f}")
        
        print("="*60)
