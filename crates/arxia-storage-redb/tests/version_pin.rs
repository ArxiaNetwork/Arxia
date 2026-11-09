//! Pin redb to the reviewed 4.4.x line.
//!
//! redb 4.1.0 carried two crash windows around file growth and resize,
//! fixed upstream in 4.2.0. They need a storage-level failure, which a
//! process kill cannot produce, so the move to 4.4.0 rests on the
//! upstream fix plus a review: the kill-nine suite passes without the
//! pre-growth mitigation and with large values, and a database written
//! by 4.1.0 was opened and extended by 4.4.0 (see
//! `docs/dependency-risks.md`). This test makes a silent drift to
//! another minor line (a lockfile bump, a Dependabot PR, a `cargo
//! update`) fail loudly until the same review happens again.
//!
//! Same mechanism as the LOW-014 pins in `arxia-core`: the lockfile is
//! the resolved truth, so the assertion reads it rather than the
//! manifest. `deny.toml` carries the matching envelope
//! (`>=4.4.0, <4.5.0`) as the conventional anchor; nothing in CI runs
//! cargo-deny today, so this test is the enforcement — which is why it
//! checks the exact envelope, not a prefix, and every resolved copy,
//! not the first: semver-incompatible duplicates resolve as separate
//! packages, and a second unvalidated copy in the tree would otherwise
//! pass unexamined. (The sequential-storage pin was hardened the same
//! way for the same reasons; the two anchors follow one pattern.)

#[test]
fn every_resolved_redb_lies_inside_the_reviewed_envelope() {
    let lock = include_str!("../../../Cargo.lock");

    let mut versions: Vec<String> = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"redb\"" {
            let v = lines
                .next()
                .expect("a [[package]] block has a version line after its name");
            versions.push(
                v.trim()
                    .strip_prefix("version = \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .expect("version line is well-formed")
                    .to_string(),
            );
        }
    }
    assert!(!versions.is_empty(), "redb must be present in Cargo.lock");

    for version in &versions {
        let mut parts = version.split('.').map(|p| {
            p.parse::<u64>()
                .expect("version components are numeric in a lockfile")
        });
        let (major, minor) = (parts.next().expect("major"), parts.next().expect("minor"));
        assert!(
            major == 4 && minor == 4,
            "redb resolved to {version}, outside the reviewed envelope \
             >=4.4.0 <4.5.0. Before accepting another line: run the \
             kill-nine suite with its large-value test, open a database \
             written by the pinned version with the candidate, update \
             docs/dependency-risks.md and deny.toml, and only then update \
             this pin. See dependency-risks.md, section \"redb crash \
             windows during file growth\"."
        );
    }
}
