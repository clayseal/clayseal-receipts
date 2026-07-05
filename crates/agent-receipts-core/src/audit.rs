use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::hash::{hash_bytes, hash_json, Hash32};
use crate::proof::ExecutionProof;

#[derive(Debug, Error)]
pub enum AuditStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain integrity violation at seq {seq}: {detail}")]
    Integrity { seq: i64, detail: String },
}

/// One append-only audit entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    pub seq: i64,
    pub proof_id: Uuid,
    pub execution_proof_hash: Hash32,
    pub action: String,
    pub authorization_context: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub prev_hash: Hash32,
    pub record_hash: Hash32,
}

impl AuditRecord {
    pub fn compute_hash(&self) -> Hash32 {
        let body = AuditRecordBody {
            seq: self.seq,
            proof_id: self.proof_id,
            execution_proof_hash: self.execution_proof_hash,
            action: self.action.clone(),
            authorization_context: self.authorization_context.clone(),
            created_at: self.created_at,
            prev_hash: self.prev_hash,
        };
        hash_json(&body).expect("audit record body must serialize")
    }
}

#[derive(Serialize)]
struct AuditRecordBody {
    seq: i64,
    proof_id: Uuid,
    execution_proof_hash: Hash32,
    action: String,
    authorization_context: serde_json::Value,
    created_at: DateTime<Utc>,
    prev_hash: Hash32,
}

/// Append-only hash-chained audit log backed by SQLite.
pub struct AuditChain {
    conn: Connection,
}

impl AuditChain {
    pub fn open(path: &str) -> Result<Self, AuditStoreError> {
        let conn = Connection::open(path)?;
        let chain = Self { conn };
        chain.migrate()?;
        Ok(chain)
    }

    pub fn in_memory() -> Result<Self, AuditStoreError> {
        let conn = Connection::open_in_memory()?;
        let chain = Self { conn };
        chain.migrate()?;
        Ok(chain)
    }

    fn migrate(&self) -> Result<(), AuditStoreError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS audit_records (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                proof_id TEXT NOT NULL,
                execution_proof_hash TEXT NOT NULL,
                action TEXT NOT NULL,
                authorization_context TEXT NOT NULL,
                created_at TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    fn tip_hash(&self) -> Result<Hash32, AuditStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT record_hash FROM audit_records ORDER BY seq DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let hex: String = row.get(0)?;
            return Ok(Hash32::from_hex(&hex).map_err(|e| {
                AuditStoreError::Integrity {
                    seq: -1,
                    detail: format!("invalid tip hash hex: {e}"),
                }
            })?);
        }
        Ok(hash_bytes(b"agent-receipts-genesis"))
    }

    pub fn append(
        &self,
        proof: &ExecutionProof,
        action: &str,
        authorization_context: serde_json::Value,
    ) -> Result<AuditRecord, AuditStoreError> {
        let prev_hash = self.tip_hash()?;
        let execution_proof_hash = hash_json(proof)?;
        let created_at = Utc::now();

        let mut record = AuditRecord {
            seq: 0,
            proof_id: proof.proof_id,
            execution_proof_hash,
            action: action.to_string(),
            authorization_context,
            created_at,
            prev_hash,
            record_hash: hash_bytes(b"placeholder"),
        };
        record.record_hash = record.compute_hash();

        let payload = serde_json::to_string(&record)?;
        self.conn.execute(
            r#"INSERT INTO audit_records
               (proof_id, execution_proof_hash, action, authorization_context,
                created_at, prev_hash, record_hash, payload)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                record.proof_id.to_string(),
                record.execution_proof_hash.hex(),
                record.action,
                serde_json::to_string(&record.authorization_context)?,
                record.created_at.to_rfc3339(),
                record.prev_hash.hex(),
                record.record_hash.hex(),
                payload,
            ],
        )?;

        let seq = self.conn.last_insert_rowid();
        record.seq = seq;
        Ok(record)
    }

    pub fn verify_chain(&self) -> Result<(), AuditStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, payload FROM audit_records ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let seq: i64 = row.get(0)?;
            let payload: String = row.get(1)?;
            Ok((seq, payload))
        })?;

        let mut expected_prev = hash_bytes(b"agent-receipts-genesis");
        for row in rows {
            let (seq, payload) = row?;
            let record: AuditRecord = serde_json::from_str(&payload)?;
            if record.prev_hash != expected_prev {
                return Err(AuditStoreError::Integrity {
                    seq,
                    detail: "prev_hash mismatch".into(),
                });
            }
            let recomputed = record.compute_hash();
            if recomputed != record.record_hash {
                return Err(AuditStoreError::Integrity {
                    seq,
                    detail: "record_hash mismatch".into(),
                });
            }
            expected_prev = record.record_hash;
        }
        Ok(())
    }

    pub fn len(&self) -> Result<usize, AuditStoreError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_records", [], |r| r.get(0))?;
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{AgentCertificate, PrincipalRef};
    use crate::proof::{AttestationPath, ExecutionProof};

    fn sample_cert() -> AgentCertificate {
        AgentCertificate {
            agent_id: Uuid::new_v4(),
            model_provenance_hash: hash_bytes(b"model-v1"),
            policy_commitment: hash_bytes(b"policy-v1"),
            principal: PrincipalRef {
                principal_id: "user-1".into(),
                organization: "acme".into(),
                scope: vec!["fraud.score".into()],
            },
            not_before: Utc::now() - chrono::Duration::hours(1),
            not_after: Utc::now() + chrono::Duration::days(30),
            issuer_signature: None,
        }
    }

    #[test]
    fn append_and_verify_chain() {
        let chain = AuditChain::in_memory().unwrap();
        let cert = sample_cert();
        let proof = ExecutionProof::from_action(
            &cert,
            hash_bytes(b"ctx"),
            hash_bytes(b"out"),
            true,
            AttestationPath::Shadow,
        );
        chain
            .append(&proof, "score_transaction", serde_json::json!({"tx": "1"}))
            .unwrap();
        chain.verify_chain().unwrap();
        assert_eq!(chain.len().unwrap(), 1);
    }
}
