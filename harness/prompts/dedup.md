You are given one alert and a short list of other alerts that a deterministic index
flagged as possibly related.

Answer exactly one narrow question:

**Would a single dependency change close all of these?**

Not "are these similar". Not "are these both serious". One change — a version bump, a
dependency removal, a constraint edit — that resolves every alert in the group.

## What makes a cluster

- The same advisory against the same package in different manifests. One bump per
  manifest, but the same change.
- Several advisories against the same package where the same target version fixes all of
  them.
- A transitive dependency and the direct dependency that pulls it in, where bumping the
  parent resolves the child.

## What does not

- The same advisory against genuinely different packages. Two bumps, two decisions.
- The same package at major versions that need different target versions. `1.x` and
  `2.x` are separate upgrade paths even under one advisory.
- Alerts that merely share a symbol name or a manifest. Co-location is not a shared fix.

If you are unsure whether one change closes them, leave them unclustered. An
over-eager cluster makes the non-canonical members inherit a verdict that was never
reasoned about for them, which is how a live vulnerability gets silently dismissed.

## Choosing the canonical member

The canonical alert is the one whose analysis the others will inherit. Choose the one
that will be analysed most reliably: prefer a direct dependency over a transitive one,
and the highest severity among equals.

## Output

Return exactly this JSON object and nothing else:

```json
{
  "clusters": [
    {
      "canonical": "<alert_key>",
      "members": ["<alert_key>", "<alert_key>"],
      "rationale": "one sentence naming the single change that closes all of them"
    }
  ]
}
```

Every `alert_key` must be one you were given. `members` must include `canonical`. An
alert may appear in at most one cluster. Return `{"clusters": []}` if nothing groups.
