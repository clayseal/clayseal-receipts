use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::pallas::Base as Fp;

/// Fixed-point scale for scores in [0, 1] → [0, SCALE].
pub const SCALE: u64 = 1_000_000;
pub const K: u32 = 12;
/// Bit width for unsigned difference witnesses.
pub const NUM_BITS: usize = 24;
/// Maximum required output fields provable in-circuit.
pub const MAX_REQUIRED_FIELDS: usize = 8;

#[derive(Clone, Debug)]
pub struct PolicyRangeConfig {
    pub instance: [Column<Instance>; 6],
    pub a: Column<Advice>,
    pub diff: Column<Advice>,
    pub b: Column<Advice>,
    pub bit: Column<Advice>,
    pub presence: Column<Advice>,
    pub q_bool: Selector,
    pub q_presence_bool: Selector,
    pub q_presence_one: Selector,
    pub q_sum_bits: Selector,
    pub q_linear: Selector,
}

#[derive(Clone, Debug)]
pub struct PolicyRangeCircuit {
    pub score: u64,
    pub min_scaled: u64,
    pub max_plus_one: u64,
    /// Field-element binding of the committed output (sha256 → field).
    pub output_commitment: Fp,
    /// Field-element binding of the committed policy document.
    pub policy_commitment: Fp,
    /// Number of required output fields (0..=MAX_REQUIRED_FIELDS).
    pub required_field_count: u8,
    /// Bitmask with the low `required_field_count` bits set when all are present.
    pub required_presence_mask: u64,
}

impl Default for PolicyRangeCircuit {
    fn default() -> Self {
        Self::from_range(0.0, 0.0, 1.0)
    }
}

impl PolicyRangeCircuit {
    pub fn from_range(score: f64, min: f64, max: f64) -> Self {
        let min_scaled = scale_f64(min);
        let max_scaled = scale_f64(max);
        Self {
            score: scale_f64(score),
            min_scaled,
            max_plus_one: max_scaled.saturating_add(1),
            output_commitment: Fp::ZERO,
            policy_commitment: Fp::ZERO,
            required_field_count: 0,
            required_presence_mask: 0,
        }
    }

    pub fn with_required_fields(mut self, count: u8, mask: u64) -> Self {
        self.required_field_count = count;
        self.required_presence_mask = mask;
        self
    }

    /// Bind the output and policy commitments (public-input field elements).
    pub fn bind(mut self, output_commitment: Fp, policy_commitment: Fp) -> Self {
        self.output_commitment = output_commitment;
        self.policy_commitment = policy_commitment;
        self
    }

    fn diff_low(&self) -> u64 {
        self.score.saturating_sub(self.min_scaled)
    }

    fn diff_high(&self) -> u64 {
        self.max_plus_one.saturating_sub(self.score)
    }

    /// Public instances: [score, min, max_plus_one, output, policy, required_mask].
    pub fn public_inputs(&self) -> Vec<Vec<Fp>> {
        vec![
            vec![Fp::from(self.score)],
            vec![Fp::from(self.min_scaled)],
            vec![Fp::from(self.max_plus_one)],
            vec![self.output_commitment],
            vec![self.policy_commitment],
            vec![Fp::from(self.required_presence_mask)],
        ]
    }
}

pub fn scale_f64(x: f64) -> u64 {
    (x.clamp(0.0, 1.0) * SCALE as f64).round() as u64
}

fn decompose_bits(v: u64) -> Vec<bool> {
    let mut bits = vec![false; NUM_BITS];
    let mut x = v;
    for i in 0..NUM_BITS {
        bits[i] = (x & 1) == 1;
        x >>= 1;
    }
    bits
}

impl Circuit<Fp> for PolicyRangeCircuit {
    type Config = PolicyRangeConfig;
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
            meta.instance_column(),
        ];
        for col in &instance {
            meta.enable_equality(*col);
        }
        let a = meta.advice_column();
        let diff = meta.advice_column();
        let b = meta.advice_column();
        let bit = meta.advice_column();
        let presence = meta.advice_column();
        for col in [a, diff, b] {
            meta.enable_equality(col);
        }

        let q_bool = meta.selector();
        let q_presence_bool = meta.selector();
        let q_presence_one = meta.selector();
        let q_sum_bits = meta.selector();
        let q_linear = meta.selector();

        meta.create_gate("bool", |meta| {
            let q = meta.query_selector(q_bool);
            let bit = meta.query_advice(bit, Rotation::cur());
            vec![q * bit.clone() * (Expression::Constant(Fp::ONE) - bit)]
        });

        meta.create_gate("presence_bool", |meta| {
            let q = meta.query_selector(q_presence_bool);
            let bit = meta.query_advice(presence, Rotation::cur());
            vec![q * bit.clone() * (Expression::Constant(Fp::ONE) - bit)]
        });

        meta.create_gate("presence_one", |meta| {
            let q = meta.query_selector(q_presence_one);
            let bit = meta.query_advice(presence, Rotation::cur());
            vec![q * (Expression::Constant(Fp::ONE) - bit)]
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

        PolicyRangeConfig {
            instance,
            a,
            diff,
            b,
            bit,
            presence,
            q_bool,
            q_presence_bool,
            q_presence_one,
            q_sum_bits,
            q_linear,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let score_cell = layouter.assign_region(
            || "score",
            |mut region| {
                region.assign_advice(
                    || "score",
                    config.a,
                    0,
                    || Value::known(Fp::from(self.score)),
                )
            },
        )?;
        layouter.constrain_instance(score_cell.cell(), config.instance[0], 0)?;

        let min_cell = layouter.assign_region(
            || "min",
            |mut region| {
                region.assign_advice(
                    || "min",
                    config.a,
                    0,
                    || Value::known(Fp::from(self.min_scaled)),
                )
            },
        )?;
        layouter.constrain_instance(min_cell.cell(), config.instance[1], 0)?;

        let max_cell = layouter.assign_region(
            || "max_plus_one",
            |mut region| {
                region.assign_advice(
                    || "max_plus_one",
                    config.a,
                    0,
                    || Value::known(Fp::from(self.max_plus_one)),
                )
            },
        )?;
        layouter.constrain_instance(max_cell.cell(), config.instance[2], 0)?;

        let output_cell = layouter.assign_region(
            || "output_commitment",
            |mut region| {
                region.assign_advice(
                    || "output_commitment",
                    config.a,
                    0,
                    || Value::known(self.output_commitment),
                )
            },
        )?;
        layouter.constrain_instance(output_cell.cell(), config.instance[3], 0)?;

        let policy_cell = layouter.assign_region(
            || "policy_commitment",
            |mut region| {
                region.assign_advice(
                    || "policy_commitment",
                    config.a,
                    0,
                    || Value::known(self.policy_commitment),
                )
            },
        )?;
        layouter.constrain_instance(policy_cell.cell(), config.instance[4], 0)?;

        let mask_cell = layouter.assign_region(
            || "required_presence_mask",
            |mut region| {
                region.assign_advice(
                    || "required_presence_mask",
                    config.a,
                    0,
                    || Value::known(Fp::from(self.required_presence_mask)),
                )
            },
        )?;
        layouter.constrain_instance(mask_cell.cell(), config.instance[5], 0)?;

        if self.required_field_count > 0 {
            assign_required_mask_bits(
                &config,
                &mut layouter,
                self.required_presence_mask,
                self.required_field_count,
            )?;
        }

        assign_diff(
            &config,
            &mut layouter,
            "min_le_score",
            &min_cell,
            self.diff_low(),
            &score_cell,
        )?;
        assign_diff(
            &config,
            &mut layouter,
            "score_lt_max",
            &score_cell,
            self.diff_high(),
            &max_cell,
        )?;

        Ok(())
    }
}

fn assign_required_mask_bits(
    config: &PolicyRangeConfig,
    layouter: &mut impl Layouter<Fp>,
    mask: u64,
    count: u8,
) -> Result<(), Error> {
    let bits = decompose_bits(mask);
    layouter.assign_region(
        || "required_field_presence",
        |mut region| {
            for (i, bit) in bits.iter().enumerate().take(MAX_REQUIRED_FIELDS) {
                config.q_presence_bool.enable(&mut region, i)?;
                region.assign_advice(
                    || format!("presence_bit_{i}"),
                    config.presence,
                    i,
                    || Value::known(if *bit { Fp::ONE } else { Fp::ZERO }),
                )?;
                if (i as u8) < count {
                    config.q_presence_one.enable(&mut region, i)?;
                }
            }
            Ok(())
        },
    )
}

fn assign_diff(
    config: &PolicyRangeConfig,
    layouter: &mut impl Layouter<Fp>,
    name: &str,
    lhs: &AssignedCell<Fp, Fp>,
    diff: u64,
    rhs: &AssignedCell<Fp, Fp>,
) -> Result<(), Error> {
    let bits = decompose_bits(diff);
    layouter.assign_region(
        || name,
        |mut region| {
            config.q_linear.enable(&mut region, 0)?;
            config.q_sum_bits.enable(&mut region, 0)?;
            lhs.copy_advice(|| "a", &mut region, config.a, 0)?;
            region.assign_advice(|| "diff", config.diff, 0, || Value::known(Fp::from(diff)))?;
            rhs.copy_advice(|| "b", &mut region, config.b, 0)?;
            for (i, bit) in bits.iter().enumerate() {
                config.q_bool.enable(&mut region, i)?;
                region.assign_advice(
                    || format!("bit_{i}"),
                    config.bit,
                    i,
                    || Value::known(if *bit { Fp::ONE } else { Fp::ZERO }),
                )?;
            }
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;

    use super::*;

    #[derive(Clone, Debug)]
    struct SplitRangeWitnessCircuit {
        public_score: u64,
        public_min: u64,
        public_max_plus_one: u64,
        range_score: u64,
        range_min: u64,
        range_max_plus_one: u64,
    }

    impl SplitRangeWitnessCircuit {
        fn public_inputs(&self) -> Vec<Vec<Fp>> {
            vec![
                vec![Fp::from(self.public_score)],
                vec![Fp::from(self.public_min)],
                vec![Fp::from(self.public_max_plus_one)],
                vec![Fp::ZERO],
                vec![Fp::ZERO],
                vec![Fp::ZERO],
            ]
        }
    }

    impl Circuit<Fp> for SplitRangeWitnessCircuit {
        type Config = PolicyRangeConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            PolicyRangeCircuit::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            fn bind_public(
                config: &PolicyRangeConfig,
                layouter: &mut impl Layouter<Fp>,
                label: &'static str,
                column: usize,
                value: Fp,
            ) -> Result<AssignedCell<Fp, Fp>, Error> {
                let cell = layouter.assign_region(
                    || label,
                    |mut region| {
                        region.assign_advice(|| label, config.a, 0, || Value::known(value))
                    },
                )?;
                layouter.constrain_instance(cell.cell(), config.instance[column], 0)?;
                Ok(cell)
            }

            let score = bind_public(
                &config,
                &mut layouter,
                "public_score",
                0,
                Fp::from(self.public_score),
            )?;
            let min = bind_public(
                &config,
                &mut layouter,
                "public_min",
                1,
                Fp::from(self.public_min),
            )?;
            let max = bind_public(
                &config,
                &mut layouter,
                "public_max_plus_one",
                2,
                Fp::from(self.public_max_plus_one),
            )?;
            let _output = bind_public(&config, &mut layouter, "output", 3, Fp::ZERO)?;
            let _policy = bind_public(&config, &mut layouter, "policy", 4, Fp::ZERO)?;
            let _mask = bind_public(&config, &mut layouter, "mask", 5, Fp::ZERO)?;

            assign_diff(
                &config,
                &mut layouter,
                "split_min_le_score",
                &min,
                self.range_score.saturating_sub(self.range_min),
                &score,
            )?;
            assign_diff(
                &config,
                &mut layouter,
                "split_score_lt_max",
                &score,
                self.range_max_plus_one.saturating_sub(self.range_score),
                &max,
            )?;
            Ok(())
        }
    }

    #[test]
    fn mock_prover_rejects_split_public_range_witnesses() {
        let circuit = SplitRangeWitnessCircuit {
            public_score: SCALE,
            public_min: 0,
            public_max_plus_one: (SCALE / 2) + 1,
            range_score: SCALE / 4,
            range_min: 0,
            range_max_plus_one: (SCALE / 2) + 1,
        };
        let prover = MockProver::run(K, &circuit, circuit.public_inputs()).unwrap();
        assert!(prover.verify().is_err());
    }
}
