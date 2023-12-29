import os
import sys
import unittest
from unittest.mock import patch
from dynamic_analysis import dynamic_main

class TestDynamicAnalysis(unittest.TestCase):
    @patch('subprocess.run')
    def test_dynamic_analysis_success(self, mock_run):
        apk_path = "SharkBot.apk"

        # Define a mock return value for subprocess.run
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "This is a simulated dynamic analysis result."
        
        analysis_result = dynamic_main.perform_dynamic_analysis(apk_path)
        
        self.assertTrue(analysis_result["Analysis Status"] == "Success")
        self.assertTrue("This is a simulated dynamic analysis result." in analysis_result["Additional Information"])

    @patch('subprocess.run')
    def test_dynamic_analysis_failure(self, mock_run):
        apk_path = "Invalid.apk"

        # Define a mock return value for subprocess.run
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "Error: Dynamic analysis failed."
        
        analysis_result = dynamic_main.perform_dynamic_analysis(apk_path)
        
        self.assertTrue(analysis_result["Analysis Status"] == "Failure")
        self.assertTrue("Error: Dynamic analysis failed." in analysis_result["Additional Information"])

if __name__ == "__main__":
    unittest.main()
