"""
A dummy AI Agent application to test our AST SAST Engine.
This contains real coding anti-patterns that our scanner must catch.
"""

def generate_ai_response():
    # VULNERABILITY 1: Hardcoded Secret
    openai_api_key = "sk-proj-1234567890abcdef"
    
    # Simulating a payload returned from an LLM
    llm_output = "print('Hello from the LLM!')"
    
    return llm_output

def execute_agent_chain():
    code_to_run = generate_ai_response()
    
    # VULNERABILITY 2: Blind execution of AI-generated code
    # If the LLM generates malicious OS commands, exec() will run them.
    exec(code_to_run)

if __name__ == "__main__":
    execute_agent_chain()