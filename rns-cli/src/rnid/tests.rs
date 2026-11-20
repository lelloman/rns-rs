use super::*;

fn ns(argv: &[&str]) -> Namespace {
    Namespace::from_args(&Args::parse_spec_from(
        argv.iter().map(|s| s.to_string()).collect(),
        &OPTIONS,
    ))
}

#[test]
fn namespace_is_argparses() {
    let parsed = ns(&["-i", "x", "-e", "a", "b", "-f"]);
    assert_eq!(parsed.encrypt, Some(vec!["a".into(), "b".into()]));
    assert!(parsed.force);
    assert_eq!(ns(&["-e"]).encrypt, Some(vec![]));
    assert_eq!(ns(&["-a"]).announce.as_deref(), Some("rns.id"));
    assert_eq!(ns(&["-S"]).sign_message, Some(MessageArg::NoMessage));
    assert_eq!(
        ns(&["-S", "hi"]).sign_message,
        Some(MessageArg::Text("hi".into()))
    );
    assert_eq!(ns(&["-E"]).embed_meta, Some(MetaArg::NoMeta));
    assert_eq!(ns(&["-t", "2.5"]).t, 2.5);
    assert_eq!(ns(&[]).t, 15.0);
    assert!(ns(&["-Z"]).base256);
    assert_eq!(ns(&["-s", "a", "-s", "b"]).sign, Some(vec!["b".into()]));
}

#[test]
fn rsg_wrapping_is_upstreams() {
    let wrapped = wrap_rsg("abc");
    let lines: Vec<&str> = wrapped.lines().collect();
    assert_eq!(
        lines[0],
        "#### Start of rsg data #########################################"
    );
    assert_eq!(lines[1], format!("abc{}", "=".repeat(61)));
    assert_eq!(
        lines[2],
        "########################################### End of rsg data ####"
    );
}

#[test]
fn destination_names_hash_as_upstream() {
    // The identity of private key bytes 0..64.
    let identity = Identity::from_private_key(&std::array::from_fn(|i| i as u8));
    assert_eq!(hexrep(identity.hash()), "aca31af0441d81dbec71e82da0b4b5f5");
    assert_eq!(
        hexrep(&hash_from_name_and_identity("app.aspect", identity.hash())),
        "e246e72c1cc4c414f117c4d9630b9444"
    );
}

#[test]
fn expanduser_is_pythons() {
    assert_eq!(expanduser("a/~"), "a/~");
    assert_eq!(expanduser("~nosuchuser12345/a"), "~nosuchuser12345/a");
    let home = std::env::var("HOME").unwrap_or_default();
    assert_eq!(
        expanduser("~/a"),
        format!("{}/a", home.trim_end_matches('/'))
    );
}
