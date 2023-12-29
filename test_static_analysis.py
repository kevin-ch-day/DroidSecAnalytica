import os
import sys
import unittest
from static_analysis import static_main

class TestStaticAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apk_path = "SharkBot-Nov-2021.apk"

    def test_static_analysis(self):
        # Redirect stdout to capture print statements
        original_stdout = sys.stdout
        sys.stdout = open(os.devnull, "w")

        try:
            static_main.execute_static_analysis(self.apk_path)

        except Exception as e:
            self.fail(f"Static analysis failed with exception: {str(e)}")

        finally:
            # Restore stdout
            sys.stdout = original_stdout

if __name__ == "__main__":
    unittest.main()
