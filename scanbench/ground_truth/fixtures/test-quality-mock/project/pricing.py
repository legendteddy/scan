from decimal import Decimal, ROUND_HALF_UP


def total_with_tax(subtotal: Decimal, tax_rate: Decimal) -> Decimal:
    if subtotal < 0:
        raise ValueError("subtotal must be non-negative")
    total = subtotal * (Decimal("1") + tax_rate)
    return total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
