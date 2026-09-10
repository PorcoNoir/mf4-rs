//! One-pass bulk decode (`signals_f64`) agrees with the per-channel path.
use mf4_rs::api::mdf::MDF;

/// Every channel of a file, read both ways, must match value-for-value
/// (NaN == NaN) and share the same axis.
fn bulk_matches_per_channel(path: &str) {
    let mdf = MDF::from_file(path).expect("open");
    let names: Vec<String> = mdf
        .channel_groups()
        .iter()
        .flat_map(|g| g.channels())
        .filter_map(|c| c.name().ok().flatten())
        .collect();
    assert!(!names.is_empty());
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();

    let bulk = mdf.signals_f64(&refs).expect("bulk read");
    assert_eq!(bulk.len(), refs.len());

    for (name, got) in refs.iter().zip(bulk) {
        let got = got.unwrap_or_else(|| panic!("bulk missed '{name}'"));
        let one = mdf
            .signal(name)
            .expect("per-channel read")
            .unwrap_or_else(|| panic!("signal() missed '{name}'"));
        let expected = one.values_f64();
        assert_eq!(got.values.len(), expected.len(), "{name}: length");
        for (i, (a, b)) in got.values.iter().zip(&expected).enumerate() {
            assert!(
                a == b || (a.is_nan() && b.is_nan()),
                "{name}[{i}]: bulk {a} vs signal {b}"
            );
        }
        assert_eq!(got.timestamps, one.timestamps, "{name}: axis");
        assert_eq!(got.unit, one.unit, "{name}: unit");
    }
}

#[test]
fn bulk_read_matches_on_a_plain_file() {
    bulk_matches_per_channel("tests/data/simple.mf4");
}

#[test]
fn bulk_read_matches_on_a_compressed_file() {
    bulk_matches_per_channel("tests/data/sample_compressed.mf4");
}

#[test]
fn unknown_names_come_back_none_in_order() {
    let mdf = MDF::from_file("tests/data/sample_compressed.mf4").expect("open");
    let first = mdf
        .channel_groups()
        .iter()
        .flat_map(|g| g.channels())
        .find_map(|c| c.name().ok().flatten())
        .expect("a named channel");
    let out = mdf
        .signals_f64(&["no_such_channel", first.as_str()])
        .expect("bulk read");
    assert!(out[0].is_none());
    assert!(out[1].is_some());
}
