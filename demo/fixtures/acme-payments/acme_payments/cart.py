"""Checkout total calculation."""

from decimal import ROUND_HALF_UP, Decimal
from typing import Union

TAX_RATE = Decimal("0.0825")
CENT = Decimal("0.01")
MoneyInput = Union[Decimal, str, int, float]  # noqa: UP007


def money(value: MoneyInput) -> Decimal:
    return Decimal(str(value)).quantize(CENT, rounding=ROUND_HALF_UP)


def checkout_total(subtotal: MoneyInput, coupon_percent: int = 0) -> Decimal:
    """Return the final checkout total.

    BUG GH-1337: coupon discounts are currently applied after sales tax.
    """
    subtotal_value = Decimal(str(subtotal))
    discount = money(subtotal_value * Decimal(str(coupon_percent)) / Decimal("100"))
    taxed = subtotal_value * (Decimal("1") + TAX_RATE)
    return money(taxed - discount)
