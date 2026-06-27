# Disclaimer — Authorized Lab Use Only

This repository contains attack simulation scripts, detection rules, and tooling intended
exclusively for use against infrastructure owned and operated by the repository author in a
controlled, isolated lab environment (Oracle Cloud VCN, private subnet).

**Do not run any attack script, scope-guarded or otherwise, against systems you do not own
or have explicit written authorization to test.**

All attack content is gated by the `siem_ir.safety` scope guard, which refuses any target
outside the configured `lab.subnets`. This is a defense-in-depth measure, not a license to
test arbitrary systems.

The author accepts no liability for misuse of the techniques, scripts, or rules in this
repository. Use responsibly and legally.
