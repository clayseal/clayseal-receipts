from decimal import Decimal
from unittest import TestCase

from acme_payments.cart import checkout_total


class CheckoutTotalTests(TestCase):
    def test_total_without_coupon_includes_tax(self) -> None:
        self.assertEqual(checkout_total("100.00"), Decimal("108.25"))
