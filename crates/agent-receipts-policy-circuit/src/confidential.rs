//! Confidential policy-range circuit (SOTA-9): prove `min <= score < max` on a **private**
//! score, revealing only a Poseidon commitment to it — never the score itself.
//!
//! Unlike [`crate::circuit::PolicyRangeCircuit`] (which exposes the score as a public
//! input), here the score and a random blinding are private witnesses. The circuit:
//!   1. hashes `Poseidon(score, blinding)` in-circuit and constrains it to a public
//!      `score_commitment` instance (binding + hiding);
//!   2. range-checks the **same** committed score cell against public `min`/`max`.
//!
//! The verifier learns the commitment, the policy bounds, and the output/policy bindings,
//! but not the score. This is the "prove policy held on `y` without revealing `y`" tier.

use ff::Field;
use group::ff::PrimeField;
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas::Base as Fp;

use crate::circuit::{scale_f64, NUM_BITS, SCALE};

pub const CONF_K: u32 = 12;

use halo2_gadgets::poseidon::primitives as poseidon;

/// Native Poseidon commitment to a scaled score under a blinding factor.
///
/// Must match the in-circuit hash so the verifier's public `score_commitment` lines up.
pub fn score_commitment(score_scaled: u64, blinding: Fp) -> Fp {
    poseidon::Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
        .hash([Fp::from(score_scaled), blinding])
}

pub fn field_to_hex(f: Fp) -> String {
    hex::encode(f.to_repr())
}

pub fn field_from_hex(s: &str) -> Result<Fp, String> {
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "score_commitment must be 32 bytes".to_string())?;
    Option::from(Fp::from_repr(arr)).ok_or_else(|| "not a canonical field element".to_string())
}

fn decompose_bits(v: u64) -> Vec<bool> {
    (0..NUM_BITS).map(|i| (v >> i) & 1 == 1).collect()
}

#[derive(Clone, Debug)]
pub struct ConfidentialConfig {
    /// [score_commitment, min, max_plus_one, output_commitment, policy_commitment]
    instance: [Column<Instance>; 5],
    a: Column<Advice>,
    diff: Column<Advice>,
    b: Column<Advice>,
    bit: Column<Advice>,
    witness: Column<Advice>,
    q_bool: Selector,
    q_sum_bits: Selector,
    q_linear: Selector,
    poseidon: Pow5Config<Fp, 3, 2>,
}

#[derive(Clone, Debug)]
pub struct ConfidentialPolicyCircuit {
    pub score: u64,
    pub blinding: Fp,
    pub min_scaled: u64,
    pub max_plus_one: u64,
    pub output_commitment: Fp,
    pub policy_commitment: Fp,
}

impl Default for ConfidentialPolicyCircuit {
    fn default() -> Self {
        Self {
            score: 0,
            blinding: Fp::ZERO,
            min_scaled: 0,
            max_plus_one: SCALE + 1,
            output_commitment: Fp::ZERO,
            policy_commitment: Fp::ZERO,
        }
    }
}

impl ConfidentialPolicyCircuit {
    pub fn new(
        score: f64,
        min: f64,
        max: f64,
        blinding: Fp,
        output_commitment: Fp,
        policy_commitment: Fp,
    ) -> Self {
        Self {
            score: scale_f64(score),
            blinding,
            min_scaled: scale_f64(min),
            max_plus_one: scale_f64(max).saturating_add(1),
            output_commitment,
            policy_commitment,
        }
    }

    /// Public instances: [score_commitment, min, max_plus_one, output, policy].
    pub fn public_inputs(&self) -> Vec<Vec<Fp>> {
        vec![
            vec![score_commitment(self.score, self.blinding)],
            vec![Fp::from(self.min_scaled)],
            vec![Fp::from(self.max_plus_one)],
            vec![self.output_commitment],
            vec![self.policy_commitment],
        ]
    }
}

impl Circuit<Fp> for ConfidentialPolicyCircuit {
    type Config = ConfidentialConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = [
            meta.instance_column(),
            meta.instance_column(),
            meta.instance_column(),
            meta.instance_column(),
            meta.instance_column(),
        ];
        for col in &instance {
            meta.enable_equality(*col);
        }
        let a = meta.advice_column();
        let diff = meta.advice_column();
        let b = meta.advice_column();
        let bit = meta.advice_column();
        let witness = meta.advice_column();
        for col in [a, diff, b, witness] {
            meta.enable_equality(col);
        }

        let q_bool = meta.selector();
        let q_sum_bits = meta.selector();
        let q_linear = meta.selector();

        meta.create_gate("bool", |meta| {
            let q = meta.query_selector(q_bool);
            let bit = meta.query_advice(bit, Rotation::cur());
            vec![q * bit.clone() * (Expression::Constant(Fp::ONE) - bit)]
        });

        meta.create_gate("sum_bits", |meta| {
            let q = meta.query_selector(q_sum_bits);
            let diff = meta.query_advice(diff, Rotation::cur());
            let mut sum = Expression::Constant(Fp::ZERO);
            for i in 0..NUM_BITS {
                let bit = meta.query_advice(bit, Rotation(i as i32));
                sum = sum + bit * Expression::Constant(Fp::from(1u64 << i));
            }
            vec![q * (diff - sum)]
        });

        meta.create_gate("linear", |meta| {
            let q = meta.query_selector(q_linear);
            let a = meta.query_advice(a, Rotation::cur());
            let diff = meta.query_advice(diff, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            vec![q * (a + diff - b)]
        });

        // Poseidon Pow5 (width 3, rate 2) over the pallas base field.
        let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        let rc_b = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<Column<Fixed>>>();
        meta.enable_constant(rc_b[0]);
        for col in &state {
            meta.enable_equality(*col);
        }
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        ConfidentialConfig {
            instance,
            a,
            diff,
            b,
            bit,
            witness,
            q_bool,
            q_sum_bits,
            q_linear,
            poseidon,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // 1. Private witnesses: score and blinding.
        let (score_cell, blinding_cell) = layouter.assign_region(
            || "private witness",
            |mut region| {
                let score = region.assign_advice(
                    || "score",
                    config.witness,
                    0,
                    || Value::known(Fp::from(self.score)),
                )?;
                let blinding = region.assign_advice(
                    || "blinding",
                    config.witness,
                    1,
                    || Value::known(self.blinding),
                )?;
                Ok((score, blinding))
            },
        )?;

        // 2. Poseidon(score, blinding) == public score_commitment.
        let chip = Pow5Chip::construct(config.poseidon.clone());
        let hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon init"),
        )?;
        let commitment = hasher.hash(
            layouter.namespace(|| "poseidon hash"),
            [score_cell.clone(), blinding_cell],
        )?;
        layouter.constrain_instance(commitment.cell(), config.instance[0], 0)?;

        // 3a. min <= score : min + diff_low = score (score copied from the committed cell).
        layouter.assign_region(
            || "min_le_score",
            |mut region| {
                config.q_linear.enable(&mut region, 0)?;
                config.q_sum_bits.enable(&mut region, 0)?;
                region.assign_advice_from_instance(|| "min", config.instance[1], 0, config.a, 0)?;
                let diff = self.score.saturating_sub(self.min_scaled);
                region.assign_advice(|| "diff", config.diff, 0, || Value::known(Fp::from(diff)))?;
                score_cell.copy_advice(|| "score", &mut region, config.b, 0)?;
                assign_bits(&config, &mut region, diff)?;
                Ok(())
            },
        )?;

        // 3b. score < max_plus_one : score + diff_high = max_plus_one.
        layouter.assign_region(
            || "score_lt_max",
            |mut region| {
                config.q_linear.enable(&mut region, 0)?;
                config.q_sum_bits.enable(&mut region, 0)?;
                score_cell.copy_advice(|| "score", &mut region, config.a, 0)?;
                let diff = self.max_plus_one.saturating_sub(self.score);
                region.assign_advice(|| "diff", config.diff, 0, || Value::known(Fp::from(diff)))?;
                region.assign_advice_from_instance(
                    || "max_plus_one",
                    config.instance[2],
                    0,
                    config.b,
                    0,
                )?;
                assign_bits(&config, &mut region, diff)?;
                Ok(())
            },
        )?;

        // 4. Bind the public output/policy commitments into the proof.
        bind_public(
            &config,
            &mut layouter,
            "output_commitment",
            self.output_commitment,
            3,
        )?;
        bind_public(
            &config,
            &mut layouter,
            "policy_commitment",
            self.policy_commitment,
            4,
        )?;

        Ok(())
    }
}

fn assign_bits(
    config: &ConfidentialConfig,
    region: &mut halo2_proofs::circuit::Region<'_, Fp>,
    diff: u64,
) -> Result<(), Error> {
    for (i, bit) in decompose_bits(diff).iter().enumerate() {
        config.q_bool.enable(region, i)?;
        region.assign_advice(
            || format!("bit_{i}"),
            config.bit,
            i,
            || Value::known(if *bit { Fp::ONE } else { Fp::ZERO }),
        )?;
    }
    Ok(())
}

fn bind_public(
    config: &ConfidentialConfig,
    layouter: &mut impl Layouter<Fp>,
    name: &str,
    value: Fp,
    instance_index: usize,
) -> Result<(), Error> {
    let cell = layouter.assign_region(
        || name,
        |mut region| region.assign_advice(|| name, config.a, 0, || Value::known(value)),
    )?;
    layouter.constrain_instance(cell.cell(), config.instance[instance_index], 0)
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;

    use super::*;

    fn circuit(score: f64, min: f64, max: f64) -> ConfidentialPolicyCircuit {
        ConfidentialPolicyCircuit::new(
            score,
            min,
            max,
            Fp::from(123_456_789u64), // fixed blinding for determinism
            Fp::from(7u64),
            Fp::from(9u64),
        )
    }

    #[test]
    fn accepts_in_range_private_score() {
        let c = circuit(0.42, 0.0, 1.0);
        let prover = MockProver::run(CONF_K, &c, c.public_inputs()).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn rejects_out_of_range_private_score() {
        let c = circuit(0.9, 0.0, 0.5);
        let prover = MockProver::run(CONF_K, &c, c.public_inputs()).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn rejects_wrong_commitment() {
        let c = circuit(0.42, 0.0, 1.0);
        let mut public = c.public_inputs();
        public[0][0] = score_commitment(c.score, Fp::from(999u64)); // wrong blinding
        let prover = MockProver::run(CONF_K, &c, public).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn rejects_tampered_bounds() {
        let c = circuit(0.42, 0.0, 1.0);
        let mut public = c.public_inputs();
        public[1][0] = Fp::from(500_000u64); // raise min above the (hidden) score
        let prover = MockProver::run(CONF_K, &c, public).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn commitment_hex_roundtrips() {
        let c = score_commitment(420_000, Fp::from(42u64));
        assert_eq!(field_from_hex(&field_to_hex(c)).unwrap(), c);
    }
}
