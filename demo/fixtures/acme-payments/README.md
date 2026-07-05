# Acme Payments Fixture

Small checkout service used by the AgentAuth Devin gate demo.

Issue `GH-1337` asks for one narrow change: fix coupon tax rounding in
`acme_payments/cart.py`, with a regression test in `tests/test_cart.py`.
