from __future__ import annotations

import unittest

from scan_core.git_change import GitChangeScope


class SemanticEfficiencyTests(unittest.TestCase):
    def test_priority_paths_consolidate_current_changed_paths(self) -> None:
        scope = GitChangeScope(
            base_ref="main",
            head_ref="HEAD",
            git_version="git version test",
            added=("src/new.py", "src/shared.py"),
            modified=("src/app.py", "src/shared.py"),
            deleted=("src/removed.py",),
            renamed=({"from": "src/old.py", "to": "src/renamed.py", "similarity": "100"},),
            copied=({"from": "src/app.py", "to": "src/copied.py", "similarity": "100"},),
            untracked=("tests/test_app.py",),
        )

        expected = (
            "src/app.py",
            "src/copied.py",
            "src/new.py",
            "src/renamed.py",
            "src/shared.py",
            "tests/test_app.py",
        )
        self.assertEqual(scope.priority_paths(), expected)
        self.assertEqual(scope.as_dict()["priority_paths"], list(expected))
        self.assertNotIn("src/removed.py", scope.priority_paths())

    def test_priority_paths_keep_safe_redacted_values_without_path_resolution(self) -> None:
        safe = "[REDACTED:path]/0123456789abcdef0123"
        scope = GitChangeScope(
            base_ref="main",
            head_ref="HEAD",
            git_version="git version test",
            modified=(safe,),
            renamed=({"from": "old.txt", "to": safe, "similarity": None},),
        )

        self.assertEqual(scope.priority_paths(), (safe,))
        self.assertEqual(scope.as_dict()["priority_paths"], [safe])

    def test_priority_paths_ignore_missing_rename_or_copy_destinations(self) -> None:
        scope = GitChangeScope(
            base_ref="main",
            head_ref="HEAD",
            git_version="git version test",
            renamed=({"from": "old.txt", "to": None, "similarity": None},),
            copied=({"from": "source.txt", "to": "", "similarity": None},),
        )

        self.assertEqual(scope.priority_paths(), ())
        self.assertEqual(scope.as_dict()["priority_paths"], [])


if __name__ == "__main__":
    unittest.main()
