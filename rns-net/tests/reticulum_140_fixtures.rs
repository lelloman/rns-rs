use serde_json::Value;

fn parse(contents: &str) -> Value {
    serde_json::from_str(contents).unwrap()
}

#[test]
fn exact_1_4_0_baseline_fixture_is_wire_stable_with_1_3_9() {
    let baseline = parse(include_str!(
        "../../tests/fixtures/conformance_1_4_0/runtime_vectors.json"
    ));
    let accepted = parse(include_str!(
        "../../tests/fixtures/conformance_1_3_9/runtime_vectors.json"
    ));

    assert_eq!(baseline["baseline"]["version"], "1.4.0");
    assert_eq!(
        baseline["baseline"]["commit"],
        "122f17fad69a483503cc5c1d8d81046712d78c96"
    );
    assert_eq!(baseline["vectors"], accepted["vectors"]);
}
