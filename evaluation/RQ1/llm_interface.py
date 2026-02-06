"""
LLM Interface for querying different language models
"""

import json
import time
import requests
from typing import Dict, Any, Optional
import logging
from config import LLM_CONFIGS, OPENAI_API_KEY, OLLAMA_BASE_URL, MAX_RETRIES, PROMPT_TEMPLATE

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMInterface:
    """Handles communication with different LLM providers"""
    
    def __init__(self, openai_api_key: str = OPENAI_API_KEY, ollama_base_url: str = OLLAMA_BASE_URL):
        self.openai_api_key = openai_api_key
        self.ollama_base_url = ollama_base_url
        self.llm_configs = LLM_CONFIGS
        
        # Validate API key
        if not self.openai_api_key or self.openai_api_key == "":
            logger.warning("OpenAI API key not configured. GPT-4o evaluations will fail.")
    
    def create_prompt(self, method_signature: str) -> str:
        """Create standardized prompt for method evaluation"""
        return PROMPT_TEMPLATE.format(method_signature=method_signature)
    
    def query_openai(self, prompt: str, config: Dict) -> str:
        """Query OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": config["model"],
            "messages": [{"role": "user", "content": prompt}],
            "temperature": config["temperature"],
            "max_tokens": config["max_tokens"]
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded")
        else:
            raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")
    
    def query_ollama(self, prompt: str, config: Dict) -> str:
        """Query Ollama local API"""
        data = {
            "model": config["model"],
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": config["temperature"]
            }
        }
        
        try:
            response = requests.post(
                f"{self.ollama_base_url}/api/generate",
                json=data,
                timeout=120
            )
            
            if response.status_code == 200:
                return response.json()["response"]
            else:
                raise Exception(f"Ollama API error: {response.status_code} - {response.text}")
        except requests.exceptions.ConnectionError:
            raise Exception("Cannot connect to Ollama. Make sure Ollama is running locally.")
    
    def parse_llm_response(self, raw_response: str) -> Dict:
        """Parse LLM response into structured format"""
        try:
            # Clean the response
            raw_response = raw_response.strip()
            
            # Remove markdown code blocks if present
            if raw_response.startswith("```json"):
                raw_response = raw_response[7:-3].strip()
            elif raw_response.startswith("```"):
                raw_response = raw_response[3:-3].strip()
            
            # Try to parse JSON
            parsed = json.loads(raw_response)
            
            # Validate required fields
            if "purpose_behavior" not in parsed:
                raise ValueError("Missing 'purpose_behavior' field")
            if "return_values" not in parsed:
                raise ValueError("Missing 'return_values' field")
            if "type" not in parsed["return_values"]:
                raise ValueError("Missing 'type' in return_values")
            if "description" not in parsed["return_values"]:
                raise ValueError("Missing 'description' in return_values")
            
            return parsed
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return {
                "purpose_behavior": f"PARSE_ERROR: {raw_response[:200]}",
                "return_values": {
                    "type": "PARSE_ERROR",
                    "description": "Failed to parse JSON response"
                },
                "parse_error": str(e)
            }
        except ValueError as e:
            logger.error(f"Validation error: {e}")
            return {
                "purpose_behavior": f"VALIDATION_ERROR: {str(e)}",
                "return_values": {
                    "type": "VALIDATION_ERROR", 
                    "description": "Response missing required fields"
                },
                "validation_error": str(e)
            }
    
    def evaluate_method(self, method_signature: str, llm_name: str) -> Dict:
        """Evaluate a single method with specified LLM"""
        if llm_name not in self.llm_configs:
            raise ValueError(f"Unknown LLM: {llm_name}")
        
        config = self.llm_configs[llm_name]
        prompt = self.create_prompt(method_signature)
        
        logger.info(f"Evaluating {method_signature} with {llm_name}")
        
        for attempt in range(MAX_RETRIES):
            try:
                # Rate limiting
                if attempt > 0:
                    time.sleep(2 ** attempt)  # Exponential backoff
                
                # Query LLM
                if config["type"] == "openai":
                    raw_response = self.query_openai(prompt, config)
                else:  # ollama
                    raw_response = self.query_ollama(prompt, config)
                
                # Parse response
                parsed_response = self.parse_llm_response(raw_response)
                
                return {
                    "llm": llm_name,
                    "method_signature": method_signature,
                    "raw_response": raw_response,
                    "parsed_response": parsed_response,
                    "success": True,
                    "attempt": attempt + 1,
                    "timestamp": time.time()
                }
                
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed for {llm_name} on {method_signature}: {str(e)}")
                
                if attempt < MAX_RETRIES - 1:
                    continue
                else:
                    return {
                        "llm": llm_name,
                        "method_signature": method_signature,
                        "error": str(e),
                        "success": False,
                        "attempt": attempt + 1,
                        "timestamp": time.time()
                    }
        
        # Apply rate limiting
        time.sleep(config.get("rate_limit_delay", 1))
        
        return result
