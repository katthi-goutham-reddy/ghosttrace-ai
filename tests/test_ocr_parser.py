import unittest
import tempfile
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from code.evidence.parsers import ImageConsoleParser, ocr_image

class TestImageConsoleParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_text_image(self, lines: list, filename: str) -> Path:
        img = Image.new("RGB", (1000, 400), color="white")
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("arial.ttf", 22)
        except Exception:
            font = None
        y = 20
        for line in lines:
            if font:
                draw.text((20, y), line, fill="black", font=font)
                y += 38
            else:
                draw.text((20, y), line, fill="black")
                y += 30
        file_path = self.dir_path / filename
        img.save(file_path)
        return file_path

    def test_blank_image_returns_no_records(self):
        """A blank image returns empty list."""
        img = Image.new("RGB", (400, 200), color="white")
        path = self.dir_path / "blank.png"
        img.save(path)

        recs = ImageConsoleParser.parse(path, "ev_blank", "2026-09-01T00:00:00Z")
        self.assertEqual(len(recs), 0)

    def test_unknown_console_returns_no_records(self):
        """An image with unrecognized console text and unknown status returns no records."""
        lines = [
            "Random Vendor Console",
            "Item status: STRANGE_STATE",
            "Non-compliant text without recognizable entities"
        ]
        path = self._create_text_image(lines, "unknown_console.png")
        recs = ImageConsoleParser.parse(path, "ev_unknown", "2026-09-01T00:00:00Z")
        self.assertEqual(len(recs), 0)

    def test_drawn_image_parsed_fields(self):
        """A synthetic image drawn with PIL parses fields correctly."""
        lines = [
            "Customer Operations",
            "| O Alice Smith Silver Filter Export Actions",
            "user_45 - account_8821",
            "alice.smith@example.com +1 555 234 5678"
        ]
        path = self._create_text_image(lines, "customer_ops.png")
        recs = ImageConsoleParser.parse(path, "ev_synthetic", "2026-09-01T00:00:00Z")
        self.assertGreaterEqual(len(recs), 1)
        acc_rec = next((r for r in recs if r.resource_id == "account_8821"), None)
        self.assertIsNotNone(acc_rec)
        self.assertEqual(acc_rec.system_id, "account_service")
        self.assertEqual(acc_rec.customer_reference, "user_45")
        self.assertEqual(acc_rec.email, "alice.smith@example.com")
        self.assertEqual(acc_rec.state, "PRESENT")

    def test_multi_row_table_record_count(self):
        """A multi-row console returns the exact count of rows found."""
        lines = [
            "BridgeOps Connections",
            "1 data_flow_101 warehouse user1@example.com Continuous Healthy",
            "2 data_flow_102 warehouse user2@example.com Continuous Healthy",
            "3 data_flow_103 warehouse user3@example.com Continuous Healthy"
        ]
        path = self._create_text_image(lines, "multi_row_connectors.png")
        recs = ImageConsoleParser.parse(path, "ev_multi", "2026-09-01T00:00:00Z")
        self.assertEqual(len(recs), 3)
        rids = {r.resource_id for r in recs}
        self.assertEqual(rids, {"data_flow_101", "data_flow_102", "data_flow_103"})

if __name__ == "__main__":
    unittest.main()
