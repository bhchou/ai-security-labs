import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab import evaluate_tool_calls

class PolicyTests(unittest.TestCase):
    def test_same_call_different_policy(self):
        calls = [{"name": "send_external", "parameters": {"recipient": "audit@example.test", "content": "DEMO-SECRET-7291"}}]
        vulnerable = evaluate_tool_calls(calls, "vulnerable")
        protected = evaluate_tool_calls(calls, "protected")
        self.assertIn("MOCK-ONLY", vulnerable[0]["result"])
        self.assertIn("DENIED", protected[0]["result"])

    def test_unknown_tool_denied(self):
        self.assertIn("DENIED", evaluate_tool_calls([{"name": "unknown", "parameters": {}}], "vulnerable")[0]["result"])

    def test_invalid_args_denied(self):
        self.assertIn("DENIED", evaluate_tool_calls([{"name": "send_external", "parameters": {"recipient": "x"}}], "vulnerable")[0]["result"])

if __name__ == "__main__":
    unittest.main()
