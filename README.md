# Volt Open Source Platform

Open technical foundation for first-generation Chevrolet Volt and Cadillac ELR research.

The platform preserves GM's original vehicle systems while providing documented, testable tools for telemetry, CAN decoding, diagnostic research, and service engineering. It is intended for engineers and experienced builders—not as a consumer programming product.

## Project family

| Repository | Responsibility |
| --- | --- |
| Volt Open Source Platform | Shared CAN/UDS knowledge, data formats, parsers, and research documentation |
| [Voltarian](https://github.com/Voltarians/Voltarian) | Android and iOS diagnostic application |
| [Voltarian ELM Lab](https://github.com/Voltarians/Voltarian-ELM-Lab) | Adapter emulator and protocol validation bench |

## Voltec CAN Toolkit

Install from a repository checkout using Python 3.10 or newer:

```bash
python -m pip install -e .
voltec --help
```

Available commands:

```text
voltec decode-frame   Decode one CAN frame
voltec decode-log     Decode a candump, ID#DATA, or CSV capture
voltec generate-dbc   Generate a DBC from signal definitions
voltec list-signals   Inspect known signals
voltec validate-dbc   Verify reproducible DBC generation
```

Examples:

```bash
voltec list-signals --can-id 0x52A
voltec decode-frame 0x4D1 "00 00 00 00 00 00 00 00" --json
voltec decode-log data/raw/candump.log data/processed/decoded.csv
voltec generate-dbc /tmp/volt_public.dbc
voltec validate-dbc
```

The original standalone parser scripts remain available under `tools/parsers`.

## Repository layout

```text
docs/       Technical documentation and cited CAN references
data/       Sanitized example captures and generated results
hardware/   Interface, wiring, and test-fixture documentation
src/        Future platform services and integrations
tools/      Reusable conversion and decoding utilities
tests/      Regression tests and known-answer vectors
```

Run validation:

```bash
python -m unittest discover -s tests -v
voltec validate-dbc
```

## Evidence policy

Every contributed signal or diagnostic definition should identify its source, applicable model years, validation vehicle or fixture, date, and confidence level. Remove VINs, account data, precise locations, and other personal information from captures.

## Safety boundary

The current public tools are read-only decoders and offline converters. Vehicle transmit, security-access, actuator-control, and programming work must remain explicitly separated, gated, documented, and tested on appropriate fixtures before vehicle use.

See [SECURITY.md](SECURITY.md) before connecting experimental software to a vehicle.

## Roadmap

1. Repository foundation and continuous validation — complete
2. Unified Voltec CAN command-line toolkit — in progress
3. Machine-readable Voltec Atlas
4. Read-only J2534/VCX module inventory scanner
5. Generated decoder definitions for Voltarian

## License

MIT. See [LICENSE](LICENSE).
