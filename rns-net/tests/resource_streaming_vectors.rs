use serde_json::Value;

#[test]
fn split_plans_match_rns_compat_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/resource/split_vectors.json"
    ))
    .unwrap();
    let maximum = fixture["max_efficient_size"].as_u64().unwrap();
    assert_eq!(
        maximum as usize,
        rns_core::constants::RESOURCE_MAX_EFFICIENT_SIZE
    );

    for vector in fixture["vectors"].as_array().unwrap() {
        let data_size = vector["data_size"].as_u64().unwrap();
        let metadata_size = vector["metadata_size"].as_u64().unwrap();
        let overhead = if metadata_size == 0 {
            0
        } else {
            metadata_size + 3
        };
        let first = data_size.min(maximum - overhead);
        let mut remaining = data_size - first;
        let mut planned = vec![first];
        while remaining > 0 {
            let length = remaining.min(maximum);
            planned.push(length);
            remaining -= length;
        }
        let expected: Vec<u64> = vector["segment_payloads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap())
            .collect();
        assert_eq!(planned, expected, "{}", vector["name"]);
    }
}
