"""Receipt exporters: the BYO-audit seam (``agentauth.core.protocols.ReceiptExporter``).

Each exporter delivers receipt bundles to one external audit/observability
target and is registered under the ``agentauth.receipt_exporters`` entry-point
group, so ``agentauth.core.plugins.get_plugin("receipt_exporters", name)``
discovers them — and third-party packages can ship their own the same way.

======================  =============================================================
Name                    Target
======================  =============================================================
``otel_genai``          OTel ``gen_ai.*`` log records over OTLP/HTTP JSON (one
                        exporter reaches Datadog, New Relic, Langfuse, LangSmith,
                        Braintrust, Splunk, …)
``ocsf_ai_operation``   OCSF ``ai_operation``-profiled API Activity events (+
                        Detection Findings for denials) for SIEM pipelines
``scitt``               Signed Statement registration with any SCRAPI
                        Transparency Service
``vanta``               Vanta Custom Resources (receipt verification as
                        continuous control evidence)
``drata``               Drata Custom Connections records
======================  =============================================================

Exporters never mutate the bundle, and receipt building never depends on an
exporter succeeding (the ``ReceiptExporter`` contract).
"""

from agentauth.receipts.exporters.drata import DrataExporter
from agentauth.receipts.exporters.evidence import receipt_evidence_record
from agentauth.receipts.exporters.ocsf import OcsfExporter
from agentauth.receipts.exporters.otel_genai import OtelGenAiExporter
from agentauth.receipts.exporters.scitt_scrapi import ScittExporter
from agentauth.receipts.exporters.vanta import VantaExporter

__all__ = [
    "DrataExporter",
    "OcsfExporter",
    "OtelGenAiExporter",
    "ScittExporter",
    "VantaExporter",
    "receipt_evidence_record",
]
