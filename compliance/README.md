# Compliance mapping (SOTA-4)

Crosswalk files in this directory map receipt bundle fields onto audit and
governance control families. See [compliance_mapping.md](../docs/compliance_mapping.md).

| Profile | File | Framework |
|---------|------|-----------|
| EU AI Act | [eu-ai-act.yaml](eu-ai-act.yaml) | Art. 12 logging, Art. 19 provenance |
| SOC 2 | [soc2.yaml](soc2.yaml) | CC6 logical access, CC7 monitoring |
| ISO 27001 | [iso27001.yaml](iso27001.yaml) | A.8.15 logging, A.8.16 monitoring |

Fixtures for SIEM ingest validation live under [fixtures/](fixtures/).
