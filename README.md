# SupersessionProof

SupersessionProof is a GenLayer Intelligent Contract that determines whether a newer rule actually replaces, revokes, overrides, amends, or otherwise displaces an older rule for an exact declared subject and scope.

It is designed as a reusable proof primitive for governance systems, protocol policies, treasury controls, compliance workflows, versioned operating rules, agent policies, and other environments where multiple rule versions may exist at the same time.

## Verdicts

SupersessionProof returns one of three semantic outcomes:

- `SUPERSEDES` — positive evidence shows that the new rule displaces the prior rule for the declared subject and material scope, with timing and applicability supporting the replacement.
- `DOES_NOT_SUPERSEDE` — positive evidence shows that the claimed replacement does not apply, for example because the rules govern different scopes, the newer rule is additive, is not yet effective, or expressly leaves the prior rule operative.
- `UNRESOLVED` — replacement language, scope, timing, applicability, version relationship, or available evidence is missing, ambiguous, conflicting, unavailable, or otherwise insufficient.

## Why it matters

A newer document does not automatically replace an older one. Real systems often contain amendments, overlapping versions, partial replacements, delayed effective dates, or rules that add to rather than supersede earlier requirements.

SupersessionProof narrows that problem to one explicit claim and requires evidence from both the prior rule and the proposed replacement.

## How it works

A case contains:

- a title
- the subject being evaluated
- an exact supersession claim
- a prior rule with a public HTTPS evidence source
- a new rule with a separate public HTTPS evidence source

The contract validates and normalizes both evidence URLs, rejects unsafe or duplicate sources, fetches bounded evidence, creates content commitments, and evaluates only the declared supersession claim through GenLayer nondeterministic execution.

Validators independently re-fetch and re-evaluate the evidence through `gl.vm.run_nondet_unsafe`, instead of blindly accepting the leader result.

Transient source failures enter a bounded retry state. Missing or unusable evidence resolves to `UNRESOLVED` instead of being treated as proof that supersession did or did not occur.

## Public methods

### Write

- `create_case(case_json: str) -> str`
- `evaluate(case_id: str) -> None`
- `retry_evaluation(case_id: str) -> None`

### View

- `get_case(case_id: str)`
- `get_evaluation(case_id: str)`
- `get_evidence(case_id: str, role: str)`
- `is_finalized(case_id: str) -> bool`
- `get_creator_case_count(creator: str) -> int`
- `get_creator_case_id(creator: str, index: int) -> str`

Evidence roles are `PRIOR_RULE` and `NEW_RULE`.

## Case schema

```json
{
  "schema_version": "1.0",
  "title": "Treasury policy replacement",
  "subject": "Treasury withdrawal policy for transfers above $50,000",
  "supersession_claim": "Treasury Policy v3 replaces the prior signer requirement in Treasury Policy v2 for withdrawals above $50,000.",
  "prior_rule": {
    "statement": "Withdrawals above $50,000 require approval from three authorized signers.",
    "label": "Treasury Policy v2",
    "source_url": "https://example.com/treasury-policy-v2.txt"
  },
  "new_rule": {
    "statement": "Effective September 1, Treasury Policy v3 replaces v2. Withdrawals above $50,000 require approval from two authorized signers.",
    "label": "Treasury Policy v3",
    "source_url": "https://example.com/treasury-policy-v3.txt"
  }
}
```

## Deployment

GenLayer Studio Dev deployment:

`0xFfD06aA489Dd3dc422CB24Cc41e437269aa4090C`

Explorer:

https://explorer-studio-dev.genlayer.com/address/0xFfD06aA489Dd3dc422CB24Cc41e437269aa4090C

## Runtime

Built for the GenLayer Studio `v0.123` release-candidate contract API using:

- `gl.contract.Contract`
- `gl.storage.TreeMap`
- GenLayer nondeterministic web access
- GenLayer LLM execution
- validator re-evaluation with `gl.vm.run_nondet_unsafe`

## Contract

The contract source is in [`contract/SupersessionProof.py`](contract/SupersessionProof.py).

An example case is available in [`examples/supersession_case.json`](examples/supersession_case.json).
