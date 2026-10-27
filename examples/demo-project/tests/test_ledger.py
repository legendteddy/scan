"""Happy-path tests; malformed CSV and rounding edge cases are not covered."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ledger import total_amount  # noqa: E402


class LedgerTests(unittest.TestCase):
    def test_one_amount(self):
        self.assertEqual(total_amount([{"amount": "2.50"}]), 2.5)

    def test_empty_rows(self):
        self.assertEqual(total_amount([]), 0)


if __name__ == "__main__":
    unittest.main()
