"""
Utility functions for framework evaluation
"""

import json
import os
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class SimilarityCalculator:
    """Handles semantic similarity calculations"""
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        try:
            self.model = SentenceTransformer(model_name)
            logger.info(f"Loaded similarity model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to load similarity model: {e}")
            raise
    
    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate cosine similarity between two texts"""
        try:
            embeddings = self.model.encode([text1, text2])
            similarity = np.dot(embeddings[0], embeddings[1]) / (
                np.linalg.norm(embeddings[0]) * np.linalg.norm(embeddings[1])
            )
            return float(similarity)
        except Exception as e:
            logger.error(f"Similarity calculation failed: {e}")
            return 0.0

def load_ground_truth(file_path: str) -> Dict:
    """Load ground truth data from JSON file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logger.info(f"Loaded ground truth from {file_path}")
        return data
    except FileNotFoundError:
        logger.error(f"Ground truth file not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in ground truth file: {e}")
        raise

def save_json(data: Dict, file_path: str):
    """Save data to JSON file"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved data to {file_path}")
    except Exception as e:
        logger.error(f"Failed to save JSON to {file_path}: {e}")
        raise

def calculate_method_similarity(ground_truth: Dict, llm_response: Dict, similarity_calc: SimilarityCalculator) -> Dict:
    """Calculate similarity scores for a method evaluation"""
    try:
        # Purpose similarity
        purpose_sim = similarity_calc.calculate_similarity(
            ground_truth["purpose_behavior"],
            llm_response["purpose_behavior"]
        )
        
        # Return type exact match
        gt_type = ground_truth["return_values"]["type"].lower().strip()
        llm_type = llm_response["return_values"]["type"].lower().strip()
        type_match = gt_type == llm_type
        
        # Return description similarity
        return_desc_sim = similarity_calc.calculate_similarity(
            ground_truth["return_values"]["description"],
            llm_response["return_values"]["description"]
        )
        
        # Overall combined similarity
        gt_combined = (
            ground_truth["purpose_behavior"] + " Returns " + 
            ground_truth["return_values"]["type"] + ": " + 
            ground_truth["return_values"]["description"]
        )
        
        llm_combined = (
            llm_response["purpose_behavior"] + " Returns " + 
            llm_response["return_values"]["type"] + ": " + 
            llm_response["return_values"]["description"]
        )
        
        overall_sim = similarity_calc.calculate_similarity(gt_combined, llm_combined)
        
        return {
            "purpose_similarity": purpose_sim,
            "return_type_match": type_match,
            "return_desc_similarity": return_desc_sim,
            "overall_similarity": overall_sim,
            "success": True
        }
        
    except Exception as e:
        logger.error(f"Similarity calculation failed: {e}")
        return {
            "purpose_similarity": 0.0,
            "return_type_match": False,
            "return_desc_similarity": 0.0,
            "overall_similarity": 0.0,
            "success": False,
            "error": str(e)
        }

def count_total_methods(ground_truth: Dict) -> int:
    """Count total number of methods in ground truth"""
    return sum(len(methods) for methods in ground_truth["framework_methods"].values())

def get_method_list(ground_truth: Dict) -> list:
    """Get flat list of all methods with their categories"""
    methods = []
    for category, method_list in ground_truth["framework_methods"].items():
        for method_data in method_list:
            methods.append({
                "signature": method_data["signature"],
                "category": category,
                "data": method_data
            })
    return methods

def create_progress_summary(results: Dict, total_methods: int) -> Dict:
    """Create summary of evaluation progress"""
    completed = len(results)
    successful_evaluations = 0
    failed_evaluations = 0
    
    for method_result in results.values():
        for llm_result in method_result.get("llm_responses", {}).values():
            if llm_result.get("success", False):
                successful_evaluations += 1
            else:
                failed_evaluations += 1
    
    return {
        "completed_methods": completed,
        "total_methods": total_methods,
        "progress_percentage": (completed / total_methods) * 100,
        "successful_evaluations": successful_evaluations,
        "failed_evaluations": failed_evaluations,
        "total_evaluations": successful_evaluations + failed_evaluations
    }
