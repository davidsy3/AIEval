## CWE-22 — Path Traversal

**What it is.** A file path is built from variable components and then opened. If those
components are untrusted, the resulting path may resolve outside the directory the program
intended to confine it to.

**What an attacker gains.** Reading files outside the intended directory, and on a write
path, creating or overwriting them. Absolute inputs are as dangerous as parent-directory
steps: joining an absolute path onto a base commonly discards the base entirely.

**Standard mitigation.** Resolve the candidate path to its canonical form, then verify it is
inside the resolved base directory before using it. Compare resolved paths; do not compare raw
strings, and do not try to strip or rewrite dangerous sequences out of the input.

**What this means for triage.** The deciding question is whether a containment check exists
*after* resolution. A join followed by a canonical-containment check is safe. Filtering
applied before resolution, or a prefix comparison on unresolved strings, usually is not.
