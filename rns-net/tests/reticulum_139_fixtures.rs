use serde_json::Value;

fn parse(contents: &str) -> Value {
    serde_json::from_str(contents).unwrap()
}

#[test]
fn exact_baseline_fixture_is_wire_stable_with_historical_1_3_8() {
    let baseline = parse(include_str!(
        "../../tests/fixtures/conformance_1_3_9/runtime_vectors.json"
    ));
    let accepted = parse(include_str!(
        "../../tests/fixtures/conformance_1_3_8/runtime_vectors.json"
    ));

    assert_eq!(baseline["baseline"]["version"], "1.3.9");
    assert_eq!(
        baseline["baseline"]["commit"],
        "cf6010da591e9361e26672b6917081a153f1f2c3"
    );
    assert_eq!(baseline["vectors"], accepted["vectors"]);
}
