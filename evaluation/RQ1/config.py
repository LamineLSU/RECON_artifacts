"""
Configuration file for Android Framework Method Evaluation
"""

import os
from typing import Dict, Any

# API Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OLLAMA_BASE_URL = "http://localhost:11434"

# File paths
GROUND_TRUTH_FILE = "framework_methods_ground_truth.json"
OUTPUT_DIR = "evaluation_results"

# LLM Configurations
LLM_CONFIGS = {
    "gpt4o": {
        "type": "openai",
        "model": "gpt-4o",
        "temperature": 0.1,
        "max_tokens": 1000,
        "rate_limit_delay": 1  # seconds between requests
    },
    "deepseek": {
        "type": "ollama", 
        "model": "deepseek-coder:6.7b",
        "temperature": 0.1,
        "rate_limit_delay": 0.5
    },
    "qwen": {
        "type": "ollama",
        "model": "qwen3-coder:latest", 
        "temperature": 0.1,
        "rate_limit_delay": 0.5
    },
    "codellama": {
        "type": "ollama",
        "model": "codellama:7b",
        "temperature": 0.1,
        "rate_limit_delay": 0.5
    },
    "llama3": {
        "type": "ollama",
        "model": "llama3.1:8b",
        "temperature": 0.1,
        "rate_limit_delay": 0.5
    }
}

# Evaluation settings
MAX_RETRIES = 3
SIMILARITY_THRESHOLD = 0.6
PROGRESS_SAVE_INTERVAL = 10  # Save progress every N methods

# Prompt template
PROMPT_TEMPLATE = """Given this Android framework method signature:
{method_signature}

Analyze this method and provide:
1. Purpose and behavior: Detailed description of what this method does
2. Return value type: The exact type this method returns
3. Return value description: What the return value represents

Format your response as JSON:
{{
  "purpose_behavior": "detailed description here",
  "return_values": {{
    "type": "exact_type_here",
    "description": "return value meaning here"
  }}
}}

Respond ONLY with the JSON, no additional text."""
