import tempfile
import unittest
from pathlib import Path

from hash_compare import compare_results, scan_path


class HashCompareTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_equal_files_with_different_names(self):
        left = self.root / "a.bin"
        right = self.root / "b.bin"
        left.write_bytes(b"same content")
        right.write_bytes(b"same content")
        result = compare_results(scan_path(left), scan_path(right))
        self.assertTrue(result.equal)
        self.assertTrue(result.conclusive)

    def test_different_files(self):
        left = self.root / "a.bin"
        right = self.root / "b.bin"
        left.write_bytes(b"left")
        right.write_bytes(b"right")
        result = compare_results(scan_path(left), scan_path(right))
        self.assertFalse(result.equal)
        self.assertEqual(result.differences[0].status, "内容不同")

    def test_equal_directories_include_empty_folders(self):
        left = self.root / "left"
        right = self.root / "right"
        for folder in (left, right):
            (folder / "empty").mkdir(parents=True)
            (folder / "nested").mkdir()
            (folder / "nested" / "中文.txt").write_text("一致", encoding="utf-8")
        result = compare_results(scan_path(left), scan_path(right))
        self.assertTrue(result.equal)
        self.assertEqual(scan_path(left).directory_count, 2)

    def test_extra_empty_folder_is_a_difference(self):
        left = self.root / "left"
        right = self.root / "right"
        left.mkdir()
        right.mkdir()
        (left / "extra").mkdir()
        result = compare_results(scan_path(left), scan_path(right))
        self.assertFalse(result.equal)
        self.assertEqual(result.differences[0].relative_path, "extra")

    def test_changed_nested_file_is_a_difference(self):
        left = self.root / "left"
        right = self.root / "right"
        left.mkdir()
        right.mkdir()
        (left / "data.txt").write_text("abc", encoding="utf-8")
        (right / "data.txt").write_text("abd", encoding="utf-8")
        result = compare_results(scan_path(left), scan_path(right))
        self.assertFalse(result.equal)
        self.assertEqual(result.differences[0].status, "内容不同")

    def test_file_and_directory_do_not_match(self):
        file_path = self.root / "file"
        directory = self.root / "folder"
        file_path.write_bytes(b"")
        directory.mkdir()
        result = compare_results(scan_path(file_path), scan_path(directory))
        self.assertFalse(result.equal)
        self.assertEqual(result.differences[0].status, "类型不同")


if __name__ == "__main__":
    unittest.main()
