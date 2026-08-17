# Contributing

Contributions should be reproducible, documented, and safe.

## Workflow

1. Open an issue describing the observation, tool, or correction.
2. Work in a branch; do not commit directly to `main`.
3. Add or update tests for code changes.
4. Run `python -m unittest discover -s tests -v`.
5. Open a pull request describing the evidence and validation performed.

## CAN and diagnostic data

For each new definition, record:

- vehicle model and model-year range
- network and CAN identifier
- byte order, start bit, length, scale, offset, and units
- source or capture method
- validation vehicle or bench fixture
- validation date
- confidence: `unverified`, `observed`, `correlated`, or `confirmed`

Do not commit VINs, registration information, account identifiers, precise locations, credentials, proprietary calibration files, or data you do not have permission to redistribute.

## Safety

Read-only research is the default. Any change that transmits to a vehicle must document the target module, request bytes, expected response, timeout behavior, recovery method, and test fixture. Programming and actuator-control changes require separate review.
