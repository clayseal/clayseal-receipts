use std::fs;
use std::path::PathBuf;

use halo2_proofs::{
    plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::commitment::Params,
};
use pasta_curves::EqAffine;

use crate::circuit::{PolicyRangeCircuit, K};
use crate::confidential::ConfidentialPolicyCircuit;

pub struct PolicyRangeKeys {
    pub params: Params<EqAffine>,
    pub vk: VerifyingKey<EqAffine>,
    pub pk: ProvingKey<EqAffine>,
}

/// Keys for the confidential policy circuit (private score + Poseidon commitment).
pub struct ConfidentialKeys {
    pub params: Params<EqAffine>,
    pub vk: VerifyingKey<EqAffine>,
    pub pk: ProvingKey<EqAffine>,
}

fn keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../keys")
}

pub fn keys_path(name: &str) -> PathBuf {
    keys_dir().join(name)
}

pub fn setup_policy_range_keys() -> Result<PolicyRangeKeys, String> {
    let params = Params::<EqAffine>::new(K);
    let empty = PolicyRangeCircuit::default();
    let vk = keygen_vk(&params, &empty).map_err(|e| format!("keygen_vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk.clone(), &empty).map_err(|e| format!("keygen_pk: {e:?}"))?;
    Ok(PolicyRangeKeys { params, vk, pk })
}

/// Load (or create + persist) the shared K-sized params used by all policy circuits.
fn load_params() -> Result<Params<EqAffine>, String> {
    let dir = keys_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let params_path = keys_path("policy_range_params.bin");
    if params_path.exists() {
        let buf = fs::read(&params_path).map_err(|e| e.to_string())?;
        Params::<EqAffine>::read(&mut buf.as_slice()).map_err(|e| format!("read params: {e}"))
    } else {
        let params = Params::<EqAffine>::new(K);
        let mut buf = vec![];
        params
            .write(&mut buf)
            .map_err(|e| format!("write params: {e}"))?;
        fs::write(&params_path, buf).map_err(|e| e.to_string())?;
        Ok(params)
    }
}

/// Derive proving/verification keys for the confidential circuit (same K params).
pub fn load_or_setup_confidential() -> Result<ConfidentialKeys, String> {
    let params = load_params()?;
    let empty = ConfidentialPolicyCircuit::default();
    let vk = keygen_vk(&params, &empty).map_err(|e| format!("keygen_vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk.clone(), &empty).map_err(|e| format!("keygen_pk: {e:?}"))?;
    Ok(ConfidentialKeys { params, vk, pk })
}

/// Load params from disk and derive proving/verification keys.
pub fn load_or_setup() -> Result<PolicyRangeKeys, String> {
    let dir = keys_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let params_path = keys_path("policy_range_params.bin");
    let params = if params_path.exists() {
        let buf = fs::read(&params_path).map_err(|e| e.to_string())?;
        Params::<EqAffine>::read(&mut buf.as_slice()).map_err(|e| format!("read params: {e}"))?
    } else {
        let keys = setup_policy_range_keys()?;
        let mut buf = vec![];
        keys.params
            .write(&mut buf)
            .map_err(|e| format!("write params: {e}"))?;
        fs::write(&params_path, buf).map_err(|e| e.to_string())?;
        keys.params
    };
    let empty = PolicyRangeCircuit::default();
    let vk = keygen_vk(&params, &empty).map_err(|e| format!("keygen_vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk.clone(), &empty).map_err(|e| format!("keygen_pk: {e:?}"))?;
    Ok(PolicyRangeKeys { params, vk, pk })
}
