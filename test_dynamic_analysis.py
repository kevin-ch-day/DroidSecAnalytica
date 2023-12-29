import os
import sys
import unittest
from unittest.mock import patch
from dynamic_analysis import dynamic_main

class TestDynamicAnalysis(unittest.TestCase):
    def test_dynamic_analysis_success(self):
        apk_path = "SharkBot.apk"
        
        # Define a mock return value for subprocess.run
        mock_run_result = MockRunResult(returncode=0, stdout="This is a simulated dynamic analysis result.")
        
        # Mock subprocess.run to return the defined result
        with patch('subprocess.run', return_value=mock_run_result):
            analysis_result = dynamic_main.perform_dynamic_analysis(apk_path)
            
            self.assertTrue(analysis_result["Analysis Status"] == "Success")
            self.assertTrue("This is a simulated dynamic analysis result." in analysis_result["Additional Information"])

    def test_dynamic_analysis_failure(self):
        apk_path = "Invalid.apk"
        
        # Define a mock return value for subprocess.run
        mock_run_result = MockRunResult(returncode=1, stdout="", stderr="Error: Dynamic analysis failed.")
        
        # Mock subprocess.run to return the defined result
        with patch('subprocess.run', return_value=mock_run_result):
            analysis_result = dynamic_main.perform_dynamic_analysis(apk_path)
            
            self.assertTrue(analysis_result["Analysis Status"] == "Failure")
            self.assertTrue("Error: Dynamic analysis failed." in analysis_result["Additional Information"])

class MockRunResult:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

if __name__ == "__main__":
    unittest.main()
