# ICSNPP-SESS

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Connection-Oriented Session Protocol (SESS)

## Overview

This plugin provides a protocol analyzer for the OSI session protocol (ISO 8327
/ X.225) for use within Zeek. The analyzer enables Zeek to parse SPDUs.

## Dependencies

As SESS is a protocol based on the OSI stack, the underlying ISO
protocol layers must also be processed. The following plugins must therefore
also be installed:

- [TPKT](https://github.com/DINA-community/icsnpp-tpkt)
- [COTP](https://github.com/DINA-community/icsnpp-cotp)

In addition, zeek must support spicy.

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html).

```bash
zkg install https://github.com/DINA-community/icsnpp-sess
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_SESS` under the list of plugins.

If users have ZKG configured to load packages (see `@load packages` in the( [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.)

## Logging

This analyzer does not log anything, but is used purely to attach the OSI presentation layer.

## License

The software was developed on behalf of the BSI (Federal Office for Information Security)

Copyright (c) 2025-2026 by DINA-Community BSD 3-Clause. [See License](/COPYING)
