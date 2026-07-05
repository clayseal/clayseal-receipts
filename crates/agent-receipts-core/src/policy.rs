use serde::{Deserialize, Serialize};

use crate::hash::Hash32;

/// How strongly a constraint class can be proven.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCapability {
    FullyProven,
    TeeAttested,
    OperatorAttested,
}

/// v1 policy tiers — see docs/policy_language.md.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTier {
    Structural,
    Schema,
    ToolTrace,
    SemanticApprox,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NumericRange {
    pub field: String,
    pub min: f64,
    pub max: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OutputSchema {
    pub fields: Vec<String>,
    pub required: Vec<String>,
}

/// Parsed policy document (YAML/JSON → canonical form → commitment hash).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyDocument {
    pub version: u32,
    pub name: String,
    pub tier: PolicyTier,
    pub capability: PolicyCapability,
    #[serde(default)]
    pub numeric_ranges: Vec<NumericRange>,
    #[serde(default)]
    pub output_schema: Option<OutputSchema>,
}

impl PolicyDocument {
    /// Canonical JSON commitment used in certificates and proofs.
    pub fn commitment(&self) -> Result<Hash32, serde_json::Error> {
        crate::hash::hash_json(self)
    }

    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }
}

/// Check structural constraints in software (Circuit 2 will mirror this logic).
pub fn check_structural(policy: &PolicyDocument, output: &serde_json::Value) -> Vec<String> {
    let mut violations = Vec::new();
    let obj = match output.as_object() {
        Some(o) => o,
        None => {
            violations.push("output must be a JSON object".into());
            return violations;
        }
    };

    if let Some(schema) = &policy.output_schema {
        for req in &schema.required {
            if !obj.contains_key(req) {
                violations.push(format!("missing required field: {req}"));
            }
        }
    }

    for range in &policy.numeric_ranges {
        let Some(v) = obj.get(&range.field) else {
            violations.push(format!("missing numeric field: {}", range.field));
            continue;
        };
        let Some(n) = v.as_f64() else {
            violations.push(format!("field {} is not numeric", range.field));
            continue;
        };
        if n < range.min || n > range.max {
            violations.push(format!(
                "{}={n} outside [{}, {}]",
                range.field, range.min, range.max
            ));
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn structural_policy_passes() {
        let yaml = r#"
version: 1
name: fraud_decision
tier: structural
capability: fully_proven
numeric_ranges:
  - field: fraud_score
    min: 0.0
    max: 1.0
output_schema:
  fields: [decision, fraud_score]
  required: [decision, fraud_score]
"#;
        let policy = PolicyDocument::from_yaml(yaml).unwrap();
        let out = json!({"decision": "review", "fraud_score": 0.42});
        assert!(check_structural(&policy, &out).is_empty());
        assert!(policy.commitment().unwrap().hex().len() == 64);
    }
}
