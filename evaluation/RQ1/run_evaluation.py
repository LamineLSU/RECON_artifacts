"""
Main execution script for Android Framework Method Evaluation
"""

import os
import sys
import logging
import argparse
from datetime import datetime

from evaluator import FrameworkMethodEvaluator
from config import GROUND_TRUTH_FILE, OPENAI_API_KEY, OUTPUT_DIR

def setup_logging(output_dir: str, log_level: str = "INFO"):
    """Setup logging configuration"""
    os.makedirs(output_dir, exist_ok=True)
    
    log_file = f"{output_dir}/evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized. Log file: {log_file}")
    return logger

def validate_setup():
    """Validate that all required files and configurations are present"""
    errors = []
    
    # Check ground truth file
    if not os.path.exists(GROUND_TRUTH_FILE):
        errors.append(f"Ground truth file not found: {GROUND_TRUTH_FILE}")
    
    # Check OpenAI API key
    if not OPENAI_API_KEY or OPENAI_API_KEY == "your-openai-api-key-here":
        errors.append("OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")
    
    # Check if sentence-transformers model can be loaded
    try:
        from sentence_transformers import SentenceTransformer
        SentenceTransformer('all-MiniLM-L6-v2')
    except Exception as e:
        errors.append(f"Cannot load sentence transformer model: {e}")
    
    return errors

def main():
    parser = argparse.ArgumentParser(description="Android Framework Method LLM Evaluation")
    parser.add_argument("--ground-truth", default=GROUND_TRUTH_FILE, 
                       help="Path to ground truth JSON file")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                       help="Output directory for results")
    parser.add_argument("--resume-from", default=None,
                       help="Resume from previous evaluation results file")
    parser.add_argument("--log-level", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Logging level")
    parser.add_argument("--dry-run", action="store_true",
                       help="Validate setup without running evaluation")
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.output_dir, args.log_level)
    
    try:
        # Validate setup
        logger.info("Validating setup...")
        validation_errors = validate_setup()
        
        if validation_errors:
            logger.error("Setup validation failed:")
            for error in validation_errors:
                logger.error(f"  - {error}")
            sys.exit(1)
        
        logger.info("Setup validation passed!")
        
        if args.dry_run:
            logger.info("Dry run complete. Setup is valid.")
            return
        
        # Initialize evaluator
        logger.info("Initializing evaluator...")
        evaluator = FrameworkMethodEvaluator(
            ground_truth_file=args.ground_truth,
            openai_api_key=OPENAI_API_KEY
        )
        
        # Run evaluation
        logger.info("Starting evaluation...")
        evaluator.run_full_evaluation(
            output_dir=args.output_dir,
            resume_from=args.resume_from
        )
        
        logger.info("Evaluation completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("Evaluation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        logger.exception("Full traceback:")
        sys.exit(1)

if __name__ == "__main__":
    main()
