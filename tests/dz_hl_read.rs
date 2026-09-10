//! Compressed MDF4 (##HL → ##DL → ##DZ): the chain that motivated this fork.
use mf4_rs::api::mdf::MDF;

#[test]
fn reads_a_compressed_mdf4_end_to_end() {
    let mdf = MDF::from_file("tests/data/sample_compressed.mf4").expect("open");
    let names: Vec<String> = mdf
        .channel_groups()
        .iter()
        .flat_map(|g| g.channels())
        .filter_map(|c| c.name().ok().flatten())
        .collect();
    assert!(!names.is_empty(), "channels enumerate: {names:?}");

    let mut read_any = false;
    for name in &names {
        let sig = mdf
            .signal(name)
            .unwrap_or_else(|e| panic!("decoding '{name}' failed: {e:?}"))
            .unwrap_or_else(|| panic!("no signal data for '{name}'"));
        let values = sig.values_f64();
        if !values.is_empty() {
            read_any = true;
        }
        if sig.has_timestamps() {
            assert_eq!(sig.timestamps.len(), values.len(), "{name}");
        }
    }
    assert!(read_any, "at least one channel yields samples");
}
