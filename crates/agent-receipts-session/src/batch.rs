//! Halo2 batch aggregation: one proof artifact over N policy_range_v3 instances.

use halo2_proofs::{
    plonk::{create_proof, verify_proof, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::EqAffine;
use rand::rngs::OsRng;
use serde_json::Value;

use agent_receipts_policy_circuit::{
    check_range, commitment_to_field, load_or_setup, required_presence_mask,
    PolicyRangeCircuit,
};

use crate::envelope::{
    build_action_refs, session_digest, validate_action_ref, SessionActionInput, SessionActionRef,
    SessionProofEnvelope, AGGREGATION_HALO2_BATCH,
};
use crate::SessionProofError;

pub(crate) fn build_circuit(action: &SessionActionInput) -> Result<PolicyRangeCircuit, SessionProofError> {
    check_range(action.score, action.min, action.max)?;
    let mask = required_presence_mask(&action.required_fields, &action.output)?;
    Ok(
        PolicyRangeCircuit::from_range(action.score, action.min, action.max)
            .bind(
                commitment_to_field(&action.output_hash),
                commitment_to_field(&action.policy_commitment),
            )
            .with_required_fields(action.required_fields.len() as u8, mask),
    )
}

fn instances_for_circuit(circuit: &PolicyRangeCircuit) -> Vec<Vec<pasta_curves::pallas::Base>> {
    circuit.public_inputs()
}

pub fn prove_session_batch(
    session_id: &str,
    actions: &[SessionActionInput],
) -> Result<SessionProofEnvelope, SessionProofError> {
    let action_refs = build_action_refs(actions)?;
    let policy_commitment = actions[0].policy_commitment.clone();
    let digest = session_digest(session_id, &action_refs)?;

    let keys = load_or_setup().map_err(SessionProofError::Prove)?;
    let circuits: Vec<PolicyRangeCircuit> = actions
        .iter()
        .map(build_circuit)
        .collect::<Result<_, _>>()?;

    let instance_sets: Vec<Vec<Vec<pasta_curves::pallas::Base>>> =
        circuits.iter().map(instances_for_circuit).collect();
    let instance_refs: Vec<Vec<&[pasta_curves::pallas::Base]>> = instance_sets
        .iter()
        .map(|set| set.iter().map(|col| col.as_slice()).collect())
        .collect();
    let outer_refs: Vec<&[&[pasta_curves::pallas::Base]]> =
        instance_refs.iter().map(|set| set.as_slice()).collect();

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        &keys.params,
        &keys.pk,
        &circuits,
        &outer_refs,
        OsRng,
        &mut transcript,
    )
    .map_err(|e| SessionProofError::Prove(format!("{e:?}")))?;

    Ok(SessionProofEnvelope {
        version: SessionProofEnvelope::VERSION,
        aggregation_mode: AGGREGATION_HALO2_BATCH.to_string(),
        session_id: session_id.to_string(),
        policy_commitment,
        action_count: actions.len() as u32,
        actions: action_refs,
        session_digest: digest,
        proof_hex: hex::encode(transcript.finalize()),
    })
}

pub fn verify_session_batch(envelope: &SessionProofEnvelope) -> Result<bool, SessionProofError> {
    if envelope.aggregation_mode != AGGREGATION_HALO2_BATCH {
        return Err(SessionProofError::Envelope(format!(
            "expected mode {AGGREGATION_HALO2_BATCH}, got {}",
            envelope.aggregation_mode
        )));
    }
    if envelope.actions.is_empty() {
        return Err(SessionProofError::Envelope("no actions in session".into()));
    }
    if envelope.action_count as usize != envelope.actions.len() {
        return Err(SessionProofError::Envelope(
            "action_count does not match actions length".into(),
        ));
    }

    let recomputed = session_digest(&envelope.session_id, &envelope.actions)?;
    if recomputed != envelope.session_digest {
        return Err(SessionProofError::Verify(
            "session_digest does not match actions".into(),
        ));
    }

    for action in &envelope.actions {
        if action.policy_commitment != envelope.policy_commitment {
            return Err(SessionProofError::Verify(
                "action policy_commitment disagrees with envelope".into(),
            ));
        }
        validate_action_ref(action)?;
    }

    let keys = load_or_setup().map_err(SessionProofError::Verify)?;
    let instance_sets = envelope
        .actions
        .iter()
        .map(instances_for_action_ref)
        .collect::<Result<Vec<_>, _>>()?;
    let instance_refs: Vec<Vec<&[pasta_curves::pallas::Base]>> = instance_sets
        .iter()
        .map(|set| set.iter().map(|col| col.as_slice()).collect())
        .collect();
    let outer_refs: Vec<&[&[pasta_curves::pallas::Base]]> =
        instance_refs.iter().map(|set| set.as_slice()).collect();

    let proof_bytes = hex::decode(&envelope.proof_hex)
        .map_err(|e| SessionProofError::Envelope(e.to_string()))?;
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof_bytes.as_slice());
    let strategy = SingleVerifier::new(&keys.params);
    verify_proof(
        &keys.params,
        &keys.vk,
        strategy,
        &outer_refs,
        &mut transcript,
    )
    .map_err(|e| SessionProofError::Verify(format!("{e:?}")))?;
    Ok(true)
}

fn instances_for_action_ref(
    action: &SessionActionRef,
) -> Result<Vec<Vec<pasta_curves::pallas::Base>>, SessionProofError> {
    let score_scaled: u64 = action
        .score_scaled
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;
    let min_scaled: u64 = action
        .min_scaled
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;
    let max_plus_one: u64 = action
        .max_plus_one
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;
    let mask: u64 = action
        .required_presence_mask
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;

    Ok(vec![
        vec![pasta_curves::pallas::Base::from(score_scaled)],
        vec![pasta_curves::pallas::Base::from(min_scaled)],
        vec![pasta_curves::pallas::Base::from(max_plus_one)],
        vec![commitment_to_field(&action.output_hash)],
        vec![commitment_to_field(&action.policy_commitment)],
        vec![pasta_curves::pallas::Base::from(mask)],
    ])
}

/// Build session actions from existing policy proof envelopes (re-proves in batch).
pub fn actions_from_policy_envelopes(
    envelopes: &[agent_receipts_policy_circuit::PolicyProofEnvelope],
    outputs: &[Value],
    mins: &[f64],
    maxs: &[f64],
) -> Result<Vec<SessionActionInput>, SessionProofError> {
    if envelopes.len() != outputs.len() {
        return Err(SessionProofError::Envelope(
            "outputs length must match envelopes".into(),
        ));
    }
    let mut actions = Vec::with_capacity(envelopes.len());
    for (index, envelope) in envelopes.iter().enumerate() {
        let score_scaled: u64 = envelope.public_inputs[0]
            .parse()
            .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;
        let min = mins.get(index).copied().unwrap_or(0.0);
        let max = maxs.get(index).copied().unwrap_or(1.0);
        let score = score_scaled as f64 / agent_receipts_policy_circuit::SCALE as f64;
        actions.push(SessionActionInput {
            score,
            min,
            max,
            policy_commitment: envelope.policy_commitment.clone(),
            output_hash: envelope.output_hash.clone(),
            required_fields: envelope.required_fields.clone(),
            output: outputs[index].clone(),
        });
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_actions(n: usize) -> Vec<SessionActionInput> {
        (0..n)
            .map(|i| SessionActionInput {
                score: 0.1 * (i as f64 + 1.0),
                min: 0.0,
                max: 1.0,
                policy_commitment: "pol-session".into(),
                output_hash: format!("out-{i}"),
                required_fields: vec!["decision".into(), "fraud_score".into()],
                output: json!({"decision": "approve", "fraud_score": 0.1 * (i as f64 + 1.0)}),
            })
            .collect()
    }

    #[test]
    fn batch_prove_verify_roundtrip() {
        let actions = sample_actions(3);
        let env = prove_session_batch("sess-1", &actions).unwrap();
        assert_eq!(env.action_count, 3);
        assert!(verify_session_batch(&env).unwrap());
    }

    #[test]
    fn batch_rejects_tampered_digest() {
        let actions = sample_actions(2);
        let mut env = prove_session_batch("sess-1", &actions).unwrap();
        env.session_digest = "deadbeef".into();
        assert!(verify_session_batch(&env).is_err());
    }

    #[test]
    fn batch_rejects_out_of_range_action() {
        let mut actions = sample_actions(1);
        actions[0].score = 2.0;
        let err = prove_session_batch("sess-1", &actions).unwrap_err();
        assert!(matches!(err, SessionProofError::Policy(_)));
    }
}
