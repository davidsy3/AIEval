# Reference material for stage 2

One file per CWE, read by `stages/triage.py` and appended to the system prompt for the
CWEs present in a case's findings. Trusted repo content, never untrusted input.

## Where the text comes from

Adapted from the per-finding `description` / `recommendation` pairs in
`../../Engine/local_analyzer.py` (the v0 offline analyzer), which is the only structure in
the project already keyed by CWE id with both a description and a mitigation. Engine2 does
not import that module, so the text is copied and generalised here rather than shared.

## The rule for editing these files

**Write from the weakness, never from the test.** `../../dataset/` is the oracle — its
README says "the fixer only ever sees `app.py`. Everything else is the answer key." Nothing
in these files may name what the dataset's security tests check: no iteration thresholds, no
list of which shell metacharacters the CWE-78 oracles use, no description of which bypass a
particular case plants. Reference text that encodes the answers turns every measurement
afterwards into a tautology.

General, published security guidance is fine. Oracle specifics are not.

## Adding more

`_reference_block()` reads `<CWE-ID>.md` for each CWE present and ignores anything missing,
so CVE excerpts or project-specific guidance can be added as further files, or appended to
these, without touching the stage.
