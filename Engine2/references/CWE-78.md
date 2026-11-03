## CWE-78 — OS Command Injection

**What it is.** A program builds a command line and hands it to a shell. If untrusted data
reaches that string, the shell interprets it as syntax, not just as an argument.

**What an attacker gains.** Execution of additional commands with the program's privileges —
reading or writing files, starting processes, reaching the network.

**Standard mitigation.** Pass an argument list to the subprocess API with no shell at all.
Then the operating system hands the arguments to the program directly and there is no shell
grammar to subvert.

**What this means for triage.** A shell is the hazard, not the subprocess call. An argument
list with `shell=False` is safe however hostile the argument. Where a shell is unavoidable,
quoting is only sound if the quoted result is not then re-interpreted by surrounding syntax,
and blocklists of forbidden characters are generally weaker than they look.
