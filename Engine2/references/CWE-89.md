## CWE-89 — SQL Injection

**What it is.** A database execution call receives a query assembled by string formatting or
concatenation. If any interpolated value is untrusted, the value can change the structure of
the statement rather than being read as data.

**What an attacker gains.** Reading rows the query was never meant to return, including other
tables via UNION; altering or deleting data; and in some drivers, running more than one
statement. The usual outcome is disclosure of the whole table.

**Standard mitigation.** Keep the SQL constant and pass every value as a bound parameter.
Interpolating a fixed identifier the program controls — a table name from a module constant
or an allowlist — is not the same thing as interpolating a value.

**What this means for triage.** The question is never "is the query an f-string?" but "is any
*untrusted* value interpolated?" A formatted query whose only interpolated part is a constant,
with user values bound, is not an instance of this weakness.
