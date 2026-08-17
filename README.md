# Volt Open Source Platform

Open technical foundation for first-generation Chevrolet Volt and Cadillac ELR research.

The platform preserves GM's original vehicle systems while providing documented, testable tools for telemetry, CAN decoding, diagnostic research, and service engineering. It is intended for engineers and experienced builders—not as a consumer programming product.

## Project family

| Repository | Responsibility |
| --- | --- |
| Volt Open Source Platform | Shared CAN/UDS knowledge, data formats, parsers, and research documentation |
| [Voltarian](https://github.com/Voltarians/Voltarian) | Android and iOS diagnostic application |
| [Voltarian ELM Lab](https://github.com/Voltarians/Voltarian-ELM-Lab) | Adapter emulator and protocol validation bench |

## Current capabilities

- Racelogic-derived public Gen-1 Volt signal definitions
- Public DBC generated from the source signal CSV
- Single-frame CAN decoder
- CAN log decoder for candump, ID#DATA, and CSV input
- Racelogic REF extraction utility
- Automated parser and DBC validation

## Repository layout

```text
docs/       Technical documentation and cited CAN references
data/       Sanitized example captures and generated results
hardware/   Interface, wiring, and test-fixture documentation
src/        Future platform services and integrations
tools/      Reusable conversion and decoding utilities
tests/      Regression tests and known-answer vectors
```

## Quick start

Python 3.10 or newer is required.

```bash
python tools/parsers/decode_frame_from_csv.py \
  docs/can/racelogic/volt_public_signals.csv \
  0xC9 \
  "00 00 00 00 00 10 27 00"

python tools/parsers/decode_log_from_csv.py \
  docs/can/racelogic/volt_public_signals.csv \
  data/raw/candump.log \
  data/processed/decoded.csv

python tools/parsers/csv_to_dbc.py \
  docs/can/racelogic/volt_public_signals.csv \
  /tmp/volt_public.dbc
```

Run the validation suite:

```bash
python -m unittest discover -s tests -v
```

## Evidence policy

Every contributed signal or diagnostic definition should identify its source, applicable model years, validation vehicle or fixture, date, and confidence level. Remove VINs, account data, precise locations, and other personal information from captures.

## Safety boundary

The current public tools are read-only decoders and offline converters. Vehicle transmit, security-access, actuator-control, and programming work must remain explicitly separated, gated, documented, and tested on appropriate fixtures before vehicle use.

See [SECURITY.md](SECURITY.md) before connecting experimental software to a vehicle.

## Roadmap

1. Repository foundation and continuous validation
2. Unified Voltec CAN command-line toolkit
3. Machine-readable Voltec Atlas
4. Read-only J2534/VCX module inventory scanner
5. Generated decoder definitions for Voltarian

## License

MIT. See [LICENSE](LICENSE).
