// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/parsec"
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

#[cfg(feature = "testing")]
#[macro_use]
extern crate criterion;
#[cfg(feature = "testing")]
#[macro_use]
extern crate unwrap;

#[cfg(feature = "testing")]
use criterion::Criterion;
#[cfg(feature = "testing")]
use parsec::dev_utils::Record;

#[cfg(feature = "testing")]
fn bench(c: &mut Criterion) {
    for name in &["minimal", "static", "dynamic"] {
        bench_dot_file(c, "benches", name);
    }

    for name in &[
        "a_node4_opaque_evt8",
        "a_node8_opaque_evt8",
        "a_node12_opaque_evt8",
        "a_node16_opaque_evt8",
        "a_node24_opaque_evt8",
        "a_node32_opaque_evt8",
        "b_node4_opaque_evt8",
        "b_node8_opaque_evt8",
        "b_node12_opaque_evt8",
        "b_node16_opaque_evt8",
        "b_node24_opaque_evt8",
        "b_node32_opaque_evt8",
        "c_node4_opaque_evt8",
        "c_node8_opaque_evt8",
        "c_node12_opaque_evt8",
        "c_node16_opaque_evt8",
        "c_node24_opaque_evt8",
        "c_node32_opaque_evt8",
    ] {
        bench_dot_file(c, "bench_section_size_evt8", name);
    }

    for name in &[
        "a_node4_opaque_evt16",
        "a_node8_opaque_evt16",
        "a_node12_opaque_evt16",
        "a_node16_opaque_evt16",
        "a_node24_opaque_evt16",
        "a_node32_opaque_evt16",
        "b_node4_opaque_evt16",
        "b_node8_opaque_evt16",
        "b_node12_opaque_evt16",
        "b_node16_opaque_evt16",
        "b_node24_opaque_evt16",
        "b_node32_opaque_evt16",
        "c_node4_opaque_evt16",
        "c_node8_opaque_evt16",
        "c_node12_opaque_evt16",
        "c_node16_opaque_evt16",
        "c_node24_opaque_evt16",
        "c_node32_opaque_evt16",
    ] {
        bench_dot_file(c, "bench_section_size_evt16", name);
    }
}

#[cfg(feature = "testing")]
fn bench_dot_file(c: &mut Criterion, group_name: &'static str, name: &'static str) {
    let _ = c.bench_function(name, move |b| {
        let record = unwrap!(Record::parse(format!(
            "input_graphs/{}/{}.dot",
            group_name, name
        )));
        b.iter_with_setup(|| record.clone(), |record| record.play())
    });
}

#[cfg(feature = "testing")]
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}

#[cfg(feature = "testing")]
criterion_main!(benches);

#[cfg(not(feature = "testing"))]
fn main() {
    println!("Benchmarks require `--features=testing`")
}
