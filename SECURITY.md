# Security and vehicle safety

## Reporting

Report software vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting feature when available. Do not open a public issue containing credentials, exploitable vehicle-control details, or personal vehicle data.

## Operational safety

- Treat the high-voltage system as lethal.
- Do not use experimental transmit code on public roads.
- Begin with an isolated bench fixture or expendable test module.
- Use a fused, current-limited supply and an independently accessible disconnect.
- Preserve logs and establish a recovery path before changing module state.
- Keep read-only discovery separate from security access, routines, actuator commands, and programming.
- Never publish credentials, seed/key secrets obtained unlawfully, VIN-linked records, or proprietary firmware without redistribution rights.

The repository maintainers cannot guarantee that experimental tooling is safe for a particular vehicle or module.
