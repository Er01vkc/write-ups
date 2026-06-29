import hashlib
import time
from flask import Flask, jsonify, request, send_from_directory
from llm_interface import IterativeAIHandler

app = Flask(__name__)

# Set the expected complexity level for proof of work
EXPECTED_COMPLEXITY = 4
recently_answered = set()

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

def verify_proof_of_work(user_input, timestamp, nonce, complexity):
    """Verify the proof of work by checking if the hash meets the complexity requirement."""
    hash_input = f"{user_input}{timestamp}{nonce}"
    hash_output = hashlib.sha256(hash_input.encode()).hexdigest()
    return hash_output.startswith('0' * complexity)

@app.route('/predict', methods=['POST'])
def predict():
    # Extract data from the JSON request
    data = request.get_json()
    
    # Extract proof-of-work related fields
    req = data.get('question')
    nonce = data.get('nonce')
    timestamp = data.get('timestamp')
    complexity = data.get('complexity')

    # Check if all required fields are provided
    if not req or nonce is None or timestamp is None or complexity is None:
        return jsonify({"error": "Incomplete proof-of-work data"}), 400

    # If complexity is lower than expected, reject the request
    if complexity < EXPECTED_COMPLEXITY:
        return jsonify({"error": "Invalid complexity. Reload the app"}), 400

    # Validate timestamp (ensure it is within an acceptable time window)
    current_time = int(time.time())
    if current_time - timestamp > 30:
        return jsonify({"error": "Proof of work expired"}), 400

    if f"{nonce}_{timestamp}" in recently_answered:
        return jsonify({"error": "Duplicate request"}), 400
    
    recently_answered.add(f"{nonce}_{timestamp}")

    # Validate proof-of-work
    if not verify_proof_of_work(req, timestamp, nonce, complexity):
        return jsonify({"error": "Invalid proof of work"}), 400

    # All checks passed, proceed with the request
    try:
        response = IterativeAIHandler().handle_request(req)
        return jsonify({"answer": response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)












import json
import os
import subprocess
import openai
from inspect import signature

MODEL = "gpt-3.5-turbo-0125"
MAX_ITERS = 5

# Set up OpenAI key
openai.api_key = os.getenv("OPENAI_API_KEY")

class ToolDispatcher:
    def __init__(self):
        self.tools = {name: func for name, func in self._get_tool_methods()}

    def _get_tool_methods(self):
        """Get all methods in the class that start with 'tool_'."""
        for attr_name in dir(self):
            if attr_name.startswith("tool_"):
                method = getattr(self, attr_name)
                yield attr_name[5:], method

    def get_registered_functions(self):
        """Get a list of registered tool functions."""
        functions_list = []
        for name, method in self.tools.items():
            docstring = method.__doc__.strip() if method.__doc__ else "No description provided."
            functions_list.append({
                "name": name,
                "description": docstring,
                "parameters": {
                    "type": "object",
                    "properties": {
                        param: {
                            "type": "string",
                            "description": f"{param} parameter"
                        } for param in self._get_method_params(method)
                    },
                    "required": self._get_method_params(method)
                }
            })
        return functions_list

    def _get_method_params(self, method):
        """Get parameters of a method, excluding 'self'."""
        sig = signature(method)
        return [param.name for param in sig.parameters.values() if param.name != 'self']

    def dispatch_tool(self, function_name, arguments):
        """Dispatch the tool based on the function name."""
        if function_name in self.tools:
            return self.tools[function_name](**arguments)
        else:
            raise ValueError(f"Function {function_name} not found.")

    def tool_list_directory(self, dir_path):
        """List files in the given directory."""
        dir_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), dir_path)
        try:
            if os.path.isdir(dir_path):
                return [
                    os.path.relpath(os.path.join(dir_path, f), os.path.dirname(os.path.abspath(__file__)))
                    for f in os.listdir(dir_path)
                ]
            else:
                return f"Error: The directory {dir_path} does not exist."
        except Exception as e:
            return f"Error listing directory {dir_path}: {e}"

    def tool_read_file(self, file_path):
        """Read the contents of the specified file."""
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
        if not os.path.abspath(file_path).startswith(os.path.dirname(os.path.abspath(__file__))):
            return "Error: You cannot read files outside of the current directory."
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r') as file:
                    return file.read()
            except Exception as e:
                return f"Error reading file {file_path}: {e}"
        else:
            return f"Error: The file {file_path} does not exist."

    def tool_forecast(self, model_path):
        """Run the forecast tool using the specified model path."""
        FORECAST_PATH = "./forecast.py"
        try:
            result = subprocess.run(
                [FORECAST_PATH, model_path],
                capture_output=True,
                text=True,
                check=False,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            return result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            return f"Error running forecast tool: {e}" 




