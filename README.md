# Governed Change Demo

## One Change. Two Gates. One Receipt.

An AI-generated change can look reasonable and still touch something it was not allowed to change or make a claim its evidence does not support.

This demo checks both.

Run the example and you will see the original change get blocked for two different reasons. Then follow the repair through a complete reevaluation and inspect the new passing receipt linked to the original failure.

This is a synthetic, deterministic demo. It evaluates a supplied snapshot of a proposed repository change. It does not inspect or modify your live worktree.

**[Run it below](#five-minute-run)** · [Follow the walkthrough](docs/FIVE_MINUTE_DEMO.md) · [Explore the engineering portfolio](https://github.com/Secondmindsystems/governed-ai-systems-portfolio)

## What happens

The original change has two problems.

It targets a path outside its declared authority, and it makes a claim the supplied evidence does not support.

A precheck first determines whether the snapshot is ready for evaluation. Then two separate gates inspect it:

- **Path Gate** checks whether the proposed repository operations stay inside the declared path authority.
- **Claims Gate** checks whether the proposed claims are supported by the declared evidence.

Both block the original revision.

The repair removes the unauthorized operation and narrows the unsupported claim. Instead of continuing from where the first attempt stopped, the repaired revision goes through the complete evaluation again.

This time both gates pass.

The new receipt links back to the original blocked receipt, so the repair does not erase the failure that came before it.

> **The first change failed. The repaired change passed. Both decisions remain part of the record.**

[Follow the five-minute walkthrough →](docs/FIVE_MINUTE_DEMO.md)

## Five-minute run

Requirements: Python 3.11 or newer.

No installation, network, credentials, provider, repository hook, or external service is required.

```bash
python3 -B -m governed_change_demo validate --fixture blocked --cap-policy policies/cap-policy.v1.json
python3 -B -m governed_change_demo demo --cap-policy policies/cap-policy.v1.json --output-dir evidence/demo-run
python3 -B -m governed_change_demo replay --fixture repaired --cap-policy policies/cap-policy.v1.json --runs 5
python3 -B -m unittest discover -s tests -v
```

The current published validation suite contains **76 passing automated tests**.

Expected replay identity:

```text
sha256:10a2135e3e8127ab8ed9d17759d8507e424d0aba2ad73afaa183bf9cf00778f4
```

The integrated demo should report:

```text
demo: PASS
blocked receipt: receipt-2bbc3c4b0305f8394b83
repaired receipt: receipt-51bbb2e71998a45e59ff
repaired receipt hash: sha256:54346099dfef791368c87c2b259e6399ebb683ec4a37e90880c0d05989e6e8d8
```

The numeric and receipt claims on this page are bound to the [machine-readable public claims manifest](evidence/public-claims.v1.json). CI reruns the evidence check whenever the repository changes:

```bash
python3 -B tools/verify_public_claims.py
```

## Try to break it

The repository includes cases for stale context, missing evidence, blocked authority, path violations, unsupported claims, and other failure conditions.

`BLOCK` means the supplied snapshot failed a required check.

`HOLD` means the available evidence cannot support a pass.

`PASS` means the supplied snapshot passed the demo's required checks. It does not execute or authorize the proposed change.

If you were not involved in building or reviewing the demo, you can [return a PASS, FAIL, or CONFUSED reproduction report](https://github.com/Secondmindsystems/governed-change-demo/issues/1).

Independent third-party reproduction on separate hardware remains pending.

## Inspect the engineering

The demo uses six structured data contracts for the proposed change, authority, precheck, gate results, combined decision, and receipt.

### How the two gates work

**Path Gate** evaluates where the proposed change operates.

**Claims Gate** evaluates what the proposed change says its evidence supports.

They return results through the same contract while applying different policies and evidence.

The complete technical material is available here:

- [Architecture](docs/ARCHITECTURE.md)
- [Five-minute walkthrough](docs/FIVE_MINUTE_DEMO.md)
- [Reproduction](docs/REPRODUCTION.md)
- [Adversarial tests](docs/ADVERSARIAL_TEST_PACK.md)
- [Verified results](docs/VERIFIED_METRICS.md)
- [Claim boundaries](docs/CLAIM_BOUNDARIES.md)

## About Second Mind Systems

Built by Tavio Lawrence as part of Second Mind Systems' work on AI harnesses, agent evaluation, authorization, developer safeguards, and inspectable execution.

[Explore the engineering portfolio](https://github.com/Secondmindsystems/governed-ai-systems-portfolio) or contact [secondmindsystems@gmail.com](mailto:secondmindsystems@gmail.com) about engineering roles, consulting, implementation, or technical collaboration.

## License

Licensed under the [Apache License 2.0](LICENSE).
