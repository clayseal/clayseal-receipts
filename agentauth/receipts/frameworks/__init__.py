"""Optional framework adapters for Agent Receipts.

These modules lazy-import third-party frameworks so the core receipts package
stays usable on its own.
"""

from agentauth.receipts.frameworks.generic import (
    ReceiptedCallable,
    default_input_adapter,
    default_output_adapter,
    output_with_receipt_metadata,
    receipted_function,
)

__all__ = [
    "ReceiptedCallable",
    "default_input_adapter",
    "default_output_adapter",
    "output_with_receipt_metadata",
    "receipted_function",
]
