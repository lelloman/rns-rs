use serde_json::Value;

fn parse(contents: &str) -> Value {
    serde_json::from_str(contents).unwrap()
}

#[test]
fn candidate_fixture_is_exact_and_wire_stable_with_accepted_1_3_8() {
    let candidate = parse(include_str!(
        "../../tests/fixtures/conformance_1_3_9/runtime_vectors.json"
    ));
    let accepted = parse(include_str!(
        "../../tests/fixtures/conformance_1_3_8/runtime_vectors.json"
    ));

    assert_eq!(candidate["baseline"]["version"], "1.3.9");
    assert_eq!(
        candidate["baseline"]["commit"],
        "cf6010da591e9361e26672b6917081a153f1f2c3"
    );
    assert_eq!(candidate["vectors"], accepted["vectors"]);
}
