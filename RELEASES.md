# Version 1.2

### UI Improvements

A lot of UI improvements

![](./docs/interface-v1.2.gif)

### New features

- Results streaming (first results appear faster) [(#59)](https://github.com/CERT-Polska/mquery/pull/59)
- Support for distributed Ursadb in the backend [(#119)](https://github.com/CERT-Polska/mquery/pull/119)
- Powerful plugin support (See the [./docs/plugins.md](documentation))
- Support for ursadb tags (for example, to tag collections as benign or malicious) [(#44)](https://github.com/CERT-Polska/mquery/pull/44)

### Improvements

- Much better Yara support [issue #41](https://github.com/CERT-Polska/mquery/issues/41):
    - Multiple rules in a query [(#55)](https://github.com/CERT-Polska/mquery/pull/55).
    - Private and global rules [(#55)](https://github.com/CERT-Polska/mquery/pull/55).
    - Case insensitive strings (`nocase` modifier) [(#136)](https://github.com/CERT-Polska/mquery/pull/136).
    - Regexes [(#169)](https://github.com/CERT-Polska/mquery/pull/169).
    - Strings that are both `ascii` and `wide` [(#65)](https://github.com/CERT-Polska/mquery/pull/65).
    - `xor` modifier (without ranges) [(#98)](https://github.com/CERT-Polska/mquery/pull/98).
    - Anonymous variables [(#66)](https://github.com/CERT-Polska/mquery/pull/66).
- Results view improvements [issue #82](https://github.com/CERT-Polska/mquery/issues/82).

### Others

- Much better workflow for new contributors [(#47)](https://github.com/CERT-Polska/mquery/pull/47).
- Improved [documentation](https://cert-polska.github.io/mquery/).

# Version 1.0

First public release

![](./docs/mquery-web-ui.gif)
