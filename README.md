# PARSEC - Protocol for Asynchronous, Reliable, Secure and Efficient Consensus

|Crate|Documentation|Linux/macOS|Windows|Issues|
|:---:|:-----------:|:---------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/parsec)](https://crates.io/crates/parsec)|[![Documentation](https://docs.rs/parsec/badge.svg)](https://docs.rs/parsec)|[![Build Status](https://travis-ci.com/maidsafe/parsec.svg?branch=master)](https://travis-ci.com/maidsafe/parsec)|[![Build status](https://ci.appveyor.com/api/projects/status/1wmc7pj8fx77lywy/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/parsec/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/parsec.png?label=ready&title=Ready)](https://waffle.io/maidsafe/parsec)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

There is a basic example available in the examples folder.  This allows you to simulate a network of peers each running the Parsec protocol to reach consensus on a number of random network events.  There is also the ability to dump each peer's gossip graph in dot format to a file in your system temp dir.  This can be enabled via the feature `dump-graphs`.  So, e.g. to run the example for a network of five peers and ten network events:

```
cargo run --release --example=basic --features=mock,dump-graphs -- --initial-peers=5 --opaque=10
```

If you have `dot` from [graphviz](https://graphviz.gitlab.io/download) available in your path, then SVG graphs will also have been generated from each of these dot files.  If not, you can copy the contents of a generated dot file into an online converter (e.g. http://viz-js.com) to view the gossip graph.

## Detailed tutorial

If the instructions in the overview are a bit sparse for your taste, please refer to the [tutorial](docs/tutorial.md) for a step-by-step guide.

## Implementation status:

### Features already implemented

- [x] Initial implementation of PARSEC
    - Demonstrates working consensus in a static network of peers
- [x] Integration tests
    - Simple tests show consensus being reached in a network of small size, with all nodes simulated in a single thread
    - Data is randomly generated to allow for soak testing
    - Soak testing has been performed for tens of thousands of run without errors
- [x] Generation of graphs
    - With the feature: `dump-graphs`, a dot representation of all network communications is output
    - The graphs are snapshots at the time each consensus decision is taken (one graph per node per consensus decision)
    - The graphs are annotated with details of the PARSEC protocol that explain how consensus was ultimately reached
    - An image (for instance .svg) can be obtained from the dot representation using dot
- [x] Reproducibility
    - In case of test failure, a seed is output. That seed can be used to reproduce the failing scenario, which helps investigate the potential issue
- [x] Simple example
    - A simple example was created to allow testing various scenarios
    - The number of peers, number of votes etc. can be configured by command line arguments
- [x] Initial documentation
    - Early documentation of the API is available [here](https://docs.rs/parsec/0.5.0/parsec/index.html)

### Upcoming features

- [ ] Foolproof handling of malice
    - Handle forks (one node sends more than one event with the same `self_parent`)
    - Double voting (one node votes more than once for the same network event)
    - Detection of malicious behaviour, resulting in consensus on excluding the offending peer
- [ ] Performance
    - Benchmark and optimise the code
    - Perform measurements of Transactions Per Second in simulated network
        - Use setup that can be compared with competing consensus protocols
- [ ] Extensive tests
    - Implement extensive tests that simulate adversarial scenarios to prove robustness outside of the "happy path"
- [ ] Extensive documentation
    - Documentation will be made comprehensive
- [ ] Dynamic network membership

## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking exception

Parsec is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify parsec, you must distribute the source to your modified version under the terms of the GPLv3.

See the [LICENSE](LICENSE) file for more details.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
