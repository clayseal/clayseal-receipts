"""AgentAuth hosted service.

Backend components:
- Identity Service  (app.identity)      -- attests workloads and issues & validates
                                           signed JWT-SVID agent credentials
- Identity event log (app.audit)        -- append-only log of credential lifecycle events
"""

__version__ = "0.2.1"
