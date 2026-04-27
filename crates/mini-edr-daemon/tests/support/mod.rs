//! Shared helpers for daemon integration tests that exercise checked-in
//! threshold fixtures through the production prediction path.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Parsed score contract for one checked-in threshold fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct ThresholdFixtureContract {
    /// Stable fixture identifier without the `.json` suffix.
    pub fixture_name: String,
    /// Natural score emitted by `training/output/model.onnx`.
    pub natural_score: f64,
    /// Inclusive lower regression bound documented for this fixture.
    pub band_low: f64,
    /// Inclusive upper regression bound documented for this fixture.
    pub band_high: f64,
}

/// Return the repository-relative path to the threshold-fixture directory.
pub fn threshold_fixture_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/feature_vectors")
}

/// Return the checked-in JSON payload path for one fixture identifier.
pub fn threshold_fixture_path(name: &str) -> PathBuf {
    threshold_fixture_directory().join(format!("{name}.json"))
}

/// Load one checked-in fixture payload as a UTF-8 JSON string.
pub fn threshold_fixture_payload(name: &str) -> String {
    fs::read_to_string(threshold_fixture_path(name))
        .unwrap_or_else(|error| panic!("read threshold fixture `{name}`: {error}"))
}

/// Load the documented threshold-fixture score table from Markdown.
pub fn load_threshold_fixture_contracts() -> BTreeMap<String, ThresholdFixtureContract> {
    let table_path = threshold_fixture_directory().join("THRESHOLD_FIXTURES.md");
    let document = fs::read_to_string(&table_path).unwrap_or_else(|error| {
        panic!(
            "read threshold fixture table `{}`: {error}",
            table_path.display()
        )
    });
    let mut contracts = BTreeMap::new();

    for line in document.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }

        let cells = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        if cells.len() < 4 || cells[0] == "fixture" || cells[0].starts_with("---") {
            continue;
        }

        let contract = ThresholdFixtureContract {
            fixture_name: cells[0].to_owned(),
            natural_score: cells[1]
                .parse::<f64>()
                .unwrap_or_else(|error| panic!("parse natural_score for `{}`: {error}", cells[0])),
            band_low: cells[2]
                .parse::<f64>()
                .unwrap_or_else(|error| panic!("parse band_low for `{}`: {error}", cells[0])),
            band_high: cells[3]
                .parse::<f64>()
                .unwrap_or_else(|error| panic!("parse band_high for `{}`: {error}", cells[0])),
        };
        contracts.insert(contract.fixture_name.clone(), contract);
    }

    contracts
}

/// Return the documented score contract for one threshold fixture.
pub fn threshold_fixture_contract(name: &str) -> ThresholdFixtureContract {
    load_threshold_fixture_contracts()
        .remove(name)
        .unwrap_or_else(|| panic!("missing documented threshold fixture contract for `{name}`"))
}

/// Assert that one observed score stays within the documented inclusive band.
pub fn assert_score_in_documented_band(name: &str, observed_score: f64) {
    let contract = threshold_fixture_contract(name);
    assert!(
        (contract.band_low..=contract.band_high).contains(&observed_score),
        "fixture `{name}` scored {observed_score:.10}, outside documented band [{:.10}, {:.10}]",
        contract.band_low,
        contract.band_high
    );
}
