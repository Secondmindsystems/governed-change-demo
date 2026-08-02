# Authorship and AI-Collaboration Disclosure

> I defined the objectives, architecture, constraints, acceptance gates, claim boundaries, and integration decisions. AI agents implemented and reviewed bounded work under those controls. Each case distinguishes my decisions from agent-generated implementation.

## Human decision ownership

The human operator defined:

- the intended capability and demonstration;
- the six contract families;
- the separation among presented authority, CAP, domain gates, Combined
  Decision, Governed Receipt, and execution;
- CAP's mechanical checks and `PASS` / `BLOCK` /
  `HOLD:CONTEXT_UPDATE_REQUIRED` taxonomy;
- Path and Claims policy boundaries;
- repair re-entry and receipt-lineage semantics;
- acceptance criteria, stop conditions, and claim ceiling; and
- the public label, license, and public/private boundary.

## AI contribution

AI agents:

- implemented schemas, policies, adapters, orchestration, receipts, fixtures,
  CLI, tests, workflow, and documentation under bounded instructions;
- ran validation and applied scoped repairs;
- reviewed contract, determinism, public-safety, and claim-boundary faults; and
- prepared this standalone export candidate.

Agent-generated implementation does not make an agent an authority issuer.
CAP does not execute, and a receipt does not grant authority.

## Lineage and implementation boundary

The public-facing label is **Context and Authority Precheck (CAP)**. Limited
internal source-project identifiers remain in stable generated compatibility
text only where changing them would alter verified deterministic outputs.
They are not public dependencies, product names, or authority claims.

The code in this repository is a native standalone prototype. It imports no
private repository package and requires no private runtime, configuration,
credential, prompt, receipt, or source-control history.

## License

The reviewed contents of this standalone repository are licensed under the
[Apache License 2.0](../LICENSE). The license does not grant trademark,
certification, endorsement, or commercial-service rights.
