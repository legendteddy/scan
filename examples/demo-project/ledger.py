"""Toy CSV totaler for a synthetic inspection example; not production finance."""
import csv
import sys


def total_amount(rows):
    """Sum an amount column from CSV records."""
    return sum(float(row["amount"]) for row in rows)


def main(path):
    with open(path, newline="", encoding="utf-8") as source:
        rows = csv.DictReader(source)
        print(f"{total_amount(rows):.2f}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python ledger.py orders.csv")
    main(sys.argv[1])
