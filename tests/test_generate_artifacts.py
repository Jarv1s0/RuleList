import tempfile
import unittest
from pathlib import Path

from scripts.generate_artifacts import build_manifest, write_readme


class GenerateArtifactsTest(unittest.TestCase):
    def test_manifest_includes_files_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            (output_dir / "ad.txt").write_text("+.example.com\n", encoding="utf-8")
            (output_dir / "ad.mrs").write_bytes(b"mrs")

            config = {
                "tasks": {
                    "ad": {
                        "behavior": "domain",
                        "format": "mrs",
                        "src": ["https://example.test/ad.txt"],
                    }
                }
            }

            manifest = build_manifest(config, output_dir, "release", "rules")

        files = manifest["artifacts"]["ad"]["files"]
        self.assertEqual(manifest["publish"]["branch"], "release")
        self.assertEqual(files[0]["path"], "ad.txt")
        self.assertEqual(files[0]["lines"], 1)
        self.assertEqual(files[1]["path"], "ad.mrs")
        self.assertIsNone(files[1]["lines"])
        self.assertEqual(len(files[0]["sha256"]), 64)

    def test_readme_prefers_mrs_provider_url(self):
        manifest = {
            "generated_at": "2026-05-11T00:00:00+08:00",
            "artifacts": {
                "ad": {
                    "behavior": "domain",
                    "sources": ["https://example.test/ad.txt"],
                    "files": [
                        {"path": "ad.txt", "bytes": 12, "lines": 1},
                        {"path": "ad.mrs", "bytes": 3, "lines": None},
                    ],
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmp:
            readme_path = Path(tmp) / "README.md"
            write_readme(readme_path, manifest, "https://raw.example/rules")
            content = readme_path.read_text(encoding="utf-8")

        self.assertIn("format: mrs", content)
        self.assertIn("https://raw.example/rules/ad.mrs", content)


if __name__ == "__main__":
    unittest.main()
