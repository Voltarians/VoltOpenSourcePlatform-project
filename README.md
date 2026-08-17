# Volt Open Source Platform

Open technical foundation for first-generation Chevrolet Volt and Cadillac ELR research.

The platform preserves GM's original vehicle systems while providing documented, testable tools for telemetry, CAN decoding, diagnostic research, and service engineering.

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

Commands:

```text
voltec decode-frame    Decode one CAN frame
voltec decode-log      Decode known signals to CSV
voltec normalize-log   Convert a supported capture to canonical CSV
voltec inspect-log     Produce a capture inventory and change report
voltec unknown-ids     List CAN IDs absent from the signal database
voltec compare-logs    Compare baseline and test captures
voltec generate-dbc    Generate a DBC from signal definitions
voltec list-signals    Inspect known signals
voltec validate-dbc    Verify reproducible DBC generation
voltec atlas ...       Validate, query, and export Voltec Atlas
```

Supported imports include SocketCAN/candump, plain `ID#DATA`, headerless byte CSV, general header-based CSV, SavvyCAN-style CSV, and common CANalyst text records.

Examples:

```bash
voltec inspect-log capture.log --output inspection.md
voltec inspect-log capture.log --json --output inspection.json
voltec normalize-log capture.log normalized.csv
voltec compare-logs ignition-off.log ready-mode.log --output comparison.md
voltec unknown-ids capture.log
voltec decode-frame 0x4D1 "00 00 00 00 00 00 00 00" --json
```

Normalized output contains only timestamp, channel, CAN ID, DLC, and payload. Unrelated source columns—including VIN or operator fields—are not carried into generated files.

## Voltec Atlas

The `atlas/` directory now holds schema-validated records for two vehicles, two networks, five principal modules, and 14 published-reference signals. Unverified diagnostic addresses remain explicitly null.

```bash
voltec atlas validate
voltec atlas lookup 0x4D1
voltec atlas export-json atlas.json
voltec atlas export-dbc atlas.dbc
```

## Repository layout

```text
docs/       Technical documentation and cited CAN references
data/       Sanitized example captures and generated results
hardware/   Interface, wiring, and test-fixture documentation
src/        Future platform services and integrations
tools/      Reusable conversion and analysis utilities
tests/      Regression tests and sanitized synthetic fixtures
```

Run validation:

```bash
python -m unittest discover -s tests -v
voltec validate-dbc
```

## Evidence and safety

Every contributed definition should identify its source, model-year applicability, validation fixture, date, and confidence. Remove VINs, accounts, precise locations, and personal information from captures.

Current public tools are offline and read-only. Vehicle transmit, security access, actuator control, and programming work remain separated and require explicit safeguards. See [SECURITY.md](SECURITY.md).

## Roadmap

1. Repository foundation and continuous validation — complete
2. Unified Voltec CAN toolkit — active
3. Machine-readable Voltec Atlas — version 0.1 operational
4. Read-only J2534/VCX module inventory scanner
5. Generated decoder definitions for Voltarian

## License

MIT. See [LICENSE](LICENSE).
