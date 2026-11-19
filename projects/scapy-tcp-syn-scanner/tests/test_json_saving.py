import json
import tempfile
import unittest
from pathlib import Path

from scanner import save_json_report, validate_output_destination


class TestJSONSaving(unittest.TestCase):

    def setUp(self):
        # Create a separate temporary directory for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.folder = Path(self.temp_dir.name)

    def test_save_valid_json(self):

        destination = self.folder / "result.json"

        report = {
            "mode": "dry-run",
            "packets_sent": 0
        }

        validate_output_destination(destination)
        save_json_report(report, destination)

        self.assertTrue(destination.exists())

        with open(destination, "r", encoding="utf-8") as file:
            saved_report = json.load(file)

        self.assertEqual(saved_report, report)

    def test_existing_file_not_overwritten(self):

        destination = self.folder / "result.json"

        original_content = '{"original": true}\n'
        destination.write_text(
            original_content,
            encoding="utf-8"
        )

        # Initial destination validation must reject the file
        with self.assertRaises(ValueError):
            validate_output_destination(destination)

        # The saving function must also prevent overwriting
        with self.assertRaises(FileExistsError):
            save_json_report(
                {"mode": "execute"},
                destination
            )

        self.assertEqual(
            destination.read_text(encoding="utf-8"),
            original_content
        )

    def test_failed_json_does_not_leave_partial_report(self):

        destination = self.folder / "result.json"

        # Python sets cannot be serialized directly to JSON
        invalid_report = {
            "ports": {22, 80}
        }

        with self.assertRaises(TypeError):
            save_json_report(invalid_report, destination)

        # The final report must not exist
        self.assertFalse(destination.exists())

        # Temporary files must also be cleaned up
        temporary_files = list(
            self.folder.glob(".scanner-*.tmp")
        )

        self.assertEqual(temporary_files, [])


if __name__ == "__main__":
    unittest.main()
