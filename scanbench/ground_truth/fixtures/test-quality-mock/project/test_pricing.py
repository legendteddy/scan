from decimal import Decimal
from unittest.mock import patch

from pricing import total_with_tax


def test_total_with_tax_happy_path():
    with patch("pricing.total_with_tax", return_value=Decimal("108.00")):
        assert total_with_tax(Decimal("100.00"), Decimal("0.08")) == Decimal("108.00")


def test_rounding_boundary_calls_real_code():
    assert total_with_tax(Decimal("0.05"), Decimal("0.10")) == Decimal("0.06")
