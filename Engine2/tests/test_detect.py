"""Stage 1 tests. Owner: ____"""

import pytest

from config import CONFIG, Config
from stages.detect import _ast_findings, _cwe_of, _dedupe, detect, detect_code
from stages.detect import _credential_crypto_findings, _finding_from_bandit
from stages.detect import _path_findings, MIN_PBKDF2_ITERATIONS
from stages.detect import _import_lines, _on_an_import
from stages.detect import _constant_only_sql, _interpolated, _is_parameterized_sql
from stages.detect import detect_tree
from fakes import VULNERABLE_APP, make_case

AST_CFG = Config(use_ast_supplement=True)


def cwes(code, cfg=CONFIG):
    """The CWEs the always-on credential/crypto rules report for `code`."""
    return {f.cwe for f in _credential_crypto_findings(code, "c", cfg)}


def rules(code, cfg=CONFIG):
    """The rule ids the always-on credential/crypto rules fire for `code`."""
    return {f.rule_id for f in _credential_crypto_findings(code, "c", cfg)}


def path_rules(code, cfg=CONFIG):
    """The rule ids the always-on CWE-22 rules fire for `code`."""
    return {f.rule_id for f in _path_findings(code, "c", cfg)}


GUARDED = """\
from pathlib import Path
def read(name, base_dir):
    base = Path(base_dir).resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise ValueError(name)
    return target.read_bytes()
"""


# --- CWE mapping and the alias table (pure, no bandit needed) ----------------

@pytest.mark.parametrize("raw,expected", [
    ("CWE-89", "CWE-89"),
    ("CWE-259", "CWE-798"),      # hard-coded password -> hard-coded credentials
    ("CWE-328", "CWE-327"),      # weak hash           -> broken crypto
    ("CWE-916", "CWE-327"),
    ("CWE-77", "CWE-78"),
    ("89", "CWE-89"),            # bare number
    ("CWE-502", None),           # not one of ours: dropped
    (None, None),
])
def test_resolved_cwe(raw, expected):
    assert CONFIG.resolved_cwe(raw) == expected


def test_cwe_read_from_bandit_json():
    assert _cwe_of({"issue_cwe": {"id": 89}}) == "CWE-89"
    assert _cwe_of({}) is None


def test_finding_built_from_bandit_result():
    finding = _finding_from_bandit({
        "issue_cwe": {"id": 259}, "line_range": [12, 13], "line_number": 12,
        "test_id": "B105", "issue_severity": "LOW", "issue_confidence": "MEDIUM",
        "issue_text": "Possible hardcoded password", "code": "PASSWORD = 'hunter2'",
    }, "case_x", CONFIG)
    assert (finding.cwe, finding.line_start, finding.line_end) == ("CWE-798", 12, 13)
    assert finding.rule_id == "B105" and finding.detector == "bandit"


def test_non_target_cwe_is_dropped():
    assert _finding_from_bandit({"issue_cwe": {"id": 502}, "line_number": 3}, "c", CONFIG) is None


# --- findings on an import line (bandit's blacklist rules) --------------------

def test_import_lines_found_by_ast_not_by_text():
    """The word `import` inside a string must not count as an import."""
    code = 'import os\nNOTE = "import subprocess"\nfrom sys import argv\n'
    assert _import_lines(code) == frozenset({1, 3})


def test_import_lines_empty_when_the_file_does_not_parse():
    assert _import_lines("def broken(:\n") == frozenset()


def test_finding_on_an_import_is_dropped():
    """B404 reports `import subprocess` as CWE-78 on the import line. An import
    is not a sink, so it can never be a real instance or match an annotation."""
    b404 = _finding_from_bandit({
        "issue_cwe": {"id": 78}, "line_range": [3], "line_number": 3,
        "test_id": "B404", "issue_text": "Consider possible security implications",
    }, "c", CONFIG)
    assert _on_an_import(b404, frozenset({3}))


def test_finding_next_to_an_import_is_kept():
    call = _finding_from_bandit({
        "issue_cwe": {"id": 78}, "line_range": [9], "line_number": 9,
        "test_id": "B602", "issue_text": "subprocess call with shell=True",
    }, "c", CONFIG)
    assert not _on_an_import(call, frozenset({1, 2, 3}))


def test_finding_spanning_an_import_and_real_code_is_kept():
    """Only a span entirely inside imports is safe to drop."""
    spanning = _finding_from_bandit({
        "issue_cwe": {"id": 78}, "line_range": [3, 4], "line_number": 3,
        "test_id": "B602", "issue_text": "x",
    }, "c", CONFIG)
    assert not _on_an_import(spanning, frozenset({3}))


def test_import_filter_is_inert_on_an_unparseable_file():
    """No import lines means nothing is dropped -- fail safe is to keep."""
    finding = _finding_from_bandit({
        "issue_cwe": {"id": 78}, "line_number": 1, "test_id": "B404",
    }, "c", CONFIG)
    assert not _on_an_import(finding, frozenset())


def test_subprocess_import_is_not_reported(tmp_path):
    """End to end: bandit does report B404 here; the stage must not pass it on."""
    code = ("import subprocess\n"
            "def run(cmd):\n"
            "    return subprocess.run(cmd, shell=True, capture_output=True)\n")
    case = make_case(tmp_path, code=code)
    findings = detect(case, CONFIG)
    assert findings, "the shell=True call itself should still be reported"
    assert all(f.line_start != 1 for f in findings)
    assert "B404" not in {f.rule_id for f in findings}


def test_dedupe_prefers_bandit_over_ast():
    from models import Finding
    bandit = Finding(case_id="c", cwe="CWE-89", line_start=5, line_end=5, detector="bandit")
    ast_dup = Finding(case_id="c", cwe="CWE-89", line_start=5, line_end=5, detector="ast")
    assert [f.detector for f in _dedupe([ast_dup, bandit])] == ["bandit"]


# --- the AST supplement (pure, no bandit needed) -----------------------------

def test_ast_supplement_finds_the_cwe_22_bandit_has_no_rule_for():
    code = ("import os\n"
            "def read(name):\n"
            "    path = os.path.join('/var/log', name)\n"
            "    with open(path) as handle:\n"
            "        return handle.read()\n")
    assert "CWE-22" in {f.cwe for f in _ast_findings(code, "c", AST_CFG)}


def test_ast_supplement_survives_a_syntax_error():
    assert _ast_findings("def broken(:\n", "c", AST_CFG) == []


def test_ast_supplement_finds_secret_literal_and_weak_hash():
    code = "import hashlib\nAPI_KEY = 'sk-live-abc'\nd = hashlib.md5(b'x').hexdigest()\n"
    cwes = {f.cwe for f in _ast_findings(code, "c", AST_CFG)}
    assert {"CWE-798", "CWE-327"} <= cwes


# --- the always-on credential rules (CWE-798) --------------------------------
# Each of these is a position bandit's B105/B106 cannot see, because those rules
# only match a wordlist against an assignment target.

def test_798_literal_returned_from_a_secret_named_function():
    code = 'def _default_secret():\n    return "whsec_4f1c8ab9d0e74217"\n'
    assert "CWE-798" in cwes(code)


def test_798_ignores_a_literal_returned_from_an_ordinary_function():
    code = 'def greeting():\n    return "hello"\n'
    assert cwes(code) == set()


def test_798_environment_lookup_with_a_literal_default():
    code = 'import os\ndef k():\n    return os.environ.get("GALLERY_KEY", "gk_live_9d21")\n'
    assert "AST-798-envdefault" in rules(code)


def test_798_environment_lookup_with_no_default_is_clean():
    """Three of the dataset's CWE-798 decoys are exactly this: it fails closed."""
    code = 'import os\ndef k():\n    return os.environ["CONFIG_HMAC_KEY"].encode()\n'
    assert cwes(code) == set()


def test_798_literal_nested_in_a_dict_under_a_credential_key():
    code = 'CONFIG = {\n    "site_root": "site",\n    "deploy_key": "dk_live_83c1",\n}\n'
    assert "AST-798-dict" in rules(code)


def test_798_ignores_a_dict_whose_keys_are_not_credentials():
    code = 'CONFIG = {\n    "site_root": "site",\n    "base_url": "https://x.invalid",\n}\n'
    assert cwes(code) == set()


def test_798_does_not_report_a_hardcoded_salt():
    """Cases 15 and 22 plant a salt as part of their CWE-327 finding; ground
    truth does not annotate it as CWE-798, so reporting it scores as an FP."""
    assert "CWE-798" not in cwes('SITE_SALT = "forum-site-salt-2019"\n')
    assert "CWE-798" not in cwes('STAFF_SALT = b"clinic-static-salt"\n')


def test_798_credential_in_a_connection_string():
    """`DB_URL` matches no wordlist, so the value is the only evidence.
    v0's analyzer had this check and Engine2 dropped it on the port."""
    code = 'DB_URL = "postgresql://admin:P@ssw0rd!@db.internal.example:5432/inventory"\n'
    assert "AST-798-literal" in rules(code)


def test_798_url_without_credentials_is_clean():
    code = 'BASE_URL = "https://example.invalid/api"\n'
    assert cwes(code) == set()


@pytest.mark.parametrize("literal", [
    "AKIAIOSFODNN7EXAMPLE",
    "sk_test_FAKE4eC39HqLyjWDarjtT1zdp7dc",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "xoxb-1234567890-abcdefghijkl",
])
def test_798_known_credential_formats_regardless_of_name(literal):
    """A published key format is a credential whatever it is called."""
    assert "AST-798-literal" in rules(f'value = "{literal}"\n')


def test_798_ordinary_literals_are_not_credentials():
    for literal in ["hello world", "SELECT * FROM users", "sha256",
                    "abc123", "application/json"]:
        assert cwes(f'value = "{literal}"\n') == set(), literal


def test_798_secret_named_attribute_target():
    """B105 does not look at attribute targets, so `app.secret_key` is missed."""
    assert "AST-798-assign" in rules('app.secret_key = "super-secret-key-123"\n')


def test_798_secret_named_assignment_outside_bandits_wordlist():
    assert "AST-798-assign" in rules('AWS_ACCESS_KEY_ID = "placeholder-value"\n')


def test_798_empty_environment_default_is_clean():
    """An empty fallback fails closed, so there is no baked-in secret."""
    code = 'import os\nWEATHER_API_KEY = os.environ.get("WEATHER_API_KEY", "")\n'
    assert cwes(code) == set()


# --- the always-on crypto rules (CWE-327) ------------------------------------

def test_327_weak_digest_named_as_an_hmac_argument():
    """B324 matches call names, so a digest passed as a string is invisible."""
    code = 'import hmac\ndef c(p):\n    return hmac.new(k(), p.encode(), "md5").hexdigest()\n'
    assert "AST-327-hmac" in rules(code)


def test_327_hmac_over_a_strong_digest_is_clean():
    code = ("import hashlib, hmac\n"
            "def c(p):\n"
            "    return hmac.new(k(), p.encode(), hashlib.sha256).hexdigest()\n")
    assert "AST-327-hmac" not in rules(code)


def test_327_weak_digest_selected_by_name():
    """`hashlib.new("md5")` -- v0 had this check; the port lost it."""
    code = 'import hashlib\nd = hashlib.new("md5", b"x").hexdigest()\n'
    assert "AST-327-newdigest" in rules(code)


def test_327_strong_digest_selected_by_name_is_clean():
    code = 'import hashlib\nd = hashlib.new("sha256", b"x").hexdigest()\n'
    assert "AST-327-newdigest" not in rules(code)


def test_78_shell_helpers_bandit_misses():
    """getoutput() always goes through a shell; B605/B607 do not list it."""
    code = 'import subprocess\ndef c(x):\n    return subprocess.getoutput("ls " + x)\n'
    assert "AST-78-shellhelper" in rules(code)


def test_78_list_argument_call_is_clean():
    code = 'import subprocess\ndef c(x):\n    return subprocess.run(["ls", x])\n'
    assert "CWE-78" not in cwes(code)


def test_327_pbkdf2_with_too_few_iterations():
    code = ("import hashlib\nITERATIONS = 1000\n"
            "def h(password, salt):\n"
            "    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)\n")
    assert "AST-327-iterations" in rules(code)


def test_327_pbkdf2_above_the_floor_is_clean():
    """The dataset's safe case stretches to 240k, so the floor must sit below it."""
    code = ("import hashlib\n"
            "def h(password, salt):\n"
            "    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 240000)\n")
    assert "AST-327-iterations" not in rules(code)
    assert MIN_PBKDF2_ITERATIONS <= 240_000


def test_327_fast_digest_over_a_password():
    """SHA-256 is not a weak hash -- it is the wrong tool for a password."""
    code = ("import hashlib\nSITE_SALT = 'x'\n"
            "def hash_password(password):\n"
            "    return hashlib.sha256((SITE_SALT + password).encode()).hexdigest()\n")
    assert "AST-327-fastdigest" in rules(code)


def test_327_fast_digest_elsewhere_is_clean():
    code = ("import hashlib\n"
            "def cache_name(name):\n"
            "    return hashlib.sha256(name.encode()).hexdigest()\n")
    assert "AST-327-fastdigest" not in rules(code)


def test_327_respects_usedforsecurity_false():
    """Four dataset decoys hash with MD5 and say so; the flag is what clears them."""
    code = ("import hashlib\n"
            "def etag(password):\n"
            "    return hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()\n")
    assert "AST-327-fastdigest" not in rules(code)


def test_credential_rules_survive_a_syntax_error():
    assert _credential_crypto_findings("def broken(:\n", "c", CONFIG) == []


def test_credential_rules_run_without_the_ast_flag():
    """They are not behind --ast: they cover shapes bandit has no rule for."""
    code = 'def _default_secret():\n    return "whsec_4f1c"\n'
    assert cwes(code, CONFIG) == {"CWE-798"}


# --- the always-on path-traversal rules (CWE-22) -----------------------------
# Bandit has no path-traversal rule, so these are the only CWE-22 coverage that
# does not need --ast. The hard part is that safe and unsafe code look the same:
# every test below pairs a flaw with the guarded version of itself.

def test_22_open_on_a_joined_path():
    code = ("import os\n"
            "def read_log(name, log_dir):\n"
            "    path = os.path.join(log_dir, name)\n"
            "    with open(path) as handle:\n"
            "        return handle.read()\n")
    assert "AST-22-sink" in path_rules(code)


def test_22_pathlib_sink_that_is_not_open():
    """Case 19 is annotated `obvious` and was missed: it never calls open()."""
    code = ("from pathlib import Path\n"
            "class C:\n"
            "    def build(self, name):\n"
            "        source = self.uploads / name\n"
            "        return source.read_bytes()\n")
    assert "AST-22-sink" in path_rules(code)


def test_22_helper_that_returns_a_built_path():
    """Ground truth annotates the builder, not each call site that uses it."""
    code = ("import os\n"
            "def _page_path(slug, site_root):\n"
            "    return os.path.join(site_root, slug + '.md')\n")
    assert "AST-22-builder" in path_rules(code)


def test_22_resolve_plus_containment_check_is_clean():
    """The idiom all five of the dataset's CWE-22 decoys use."""
    assert path_rules(GUARDED) == set()


def test_22_guard_carries_to_callers_of_a_guarded_helper():
    """In the clean cases a guarded helper returns the path and other
    functions just use it; without propagation every one would be reported."""
    code = ("from pathlib import Path\n"
            "class C:\n"
            "    def _locate(self, name):\n"
            "        base = self.root.resolve()\n"
            "        path = (base / name).resolve()\n"
            "        if not path.is_relative_to(base):\n"
            "            raise ValueError(name)\n"
            "        return path\n"
            "    def fetch(self, name):\n"
            "        return self._locate(name).read_bytes()\n")
    assert path_rules(code) == set()


def test_22_a_broken_strip_guard_is_still_reported():
    """Case 11: one `../` strip pass, so `....//` survives it."""
    code = ("import os\n"
            "def _strip(name):\n"
            "    return name.replace('../', '')\n"
            "def template_path(name, d):\n"
            "    return os.path.join(d, _strip(name) + '.tpl')\n")
    assert "AST-22-builder" in path_rules(code)


def test_22_a_prefix_check_without_a_separator_is_still_reported():
    """Case 12: `startswith` with no separator, so `/base-evil` passes."""
    code = ("import os\n"
            "def _inside(path, base):\n"
            "    return os.path.abspath(path).startswith(os.path.abspath(base))\n"
            "def export_path(name, base):\n"
            "    candidate = os.path.join(base, name)\n"
            "    if not _inside(candidate, base):\n"
            "        raise ValueError(name)\n"
            "    return candidate\n")
    assert "AST-22-builder" in path_rules(code)


def test_22_rejecting_non_bare_filenames_is_clean():
    """Requiring the final component to equal the requested name leaves no
    room for a separator or a `..` step."""
    code = ("from pathlib import Path\n"
            "class C:\n"
            "    def _resolve(self, filename):\n"
            "        path = self.log_dir / filename\n"
            "        if path.name != filename or not path.is_file():\n"
            "            raise FileNotFoundError(filename)\n"
            "        return path\n")
    assert path_rules(code) == set()


def test_22_appending_a_constant_is_clean():
    code = ("from pathlib import Path\n"
            "class C:\n"
            "    def __init__(self, base):\n"
            "        self.base = Path(base)\n"
            "        self.uploads = self.base / 'uploads'\n"
            "        self.uploads.mkdir(parents=True, exist_ok=True)\n")
    assert path_rules(code) == set()


def test_22_plain_string_concatenation_is_not_a_path():
    """`md5(...) + SUFFIX` builds a cache filename. Treating every
    concatenation as path construction reported three decoys."""
    code = ("import hashlib\n"
            "def cache_name(name):\n"
            "    return hashlib.md5(name.encode(), usedforsecurity=False)"
            ".hexdigest() + '.thumb'\n")
    assert path_rules(code) == set()


def test_22_one_finding_per_function():
    """A function that builds a path and uses it twice has one flaw, and
    findings are scored one-to-one against annotations."""
    code = ("from pathlib import Path\n"
            "def copy(name, base):\n"
            "    src = Path(base) / name\n"
            "    data = src.read_bytes()\n"
            "    (Path(base) / (name + '.bak')).write_bytes(data)\n"
            "    return data\n")
    assert len(_path_findings(code, "c", CONFIG)) == 1


def test_22_survives_a_syntax_error():
    assert _path_findings("def broken(:\n", "c", CONFIG) == []


def test_22_runs_without_the_ast_flag():
    code = ("import os\n"
            "def _page_path(slug, root):\n"
            "    return os.path.join(root, slug + '.md')\n")
    assert path_rules(code, CONFIG) == {"AST-22-builder"}


# --- bandit itself -----------------------------------------------------------

def test_detect_reports_sql_injection(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    findings = detect(case, CONFIG)
    assert findings, "bandit should report the f-stringed query"
    assert "CWE-89" in {f.cwe for f in findings}
    assert all(f.case_id == case.case_id for f in findings)


def test_detect_reports_the_planted_flaw_and_not_the_look_alike(tmp_path):
    """VULNERABLE_APP is "one planted flaw and one safe look-alike".

    The flaw interpolates `name` into the query; the look-alike interpolates the
    TABLE constant and binds the value. Stage 1 is allowed to over-flag, but it
    is not required to, and reporting the safe one would be a plain error.

    This used to assert `len(findings) > len(case.vulns)`, which passed only
    because B608 reported the look-alike too.
    """
    case = make_case(tmp_path, code=VULNERABLE_APP)
    findings = detect(case, CONFIG)
    reported = {f.line_start for f in findings if f.cwe == "CWE-89"}
    planted = case.vulns[0].line_start
    assert planted in reported, "the f-stringed value must be reported"
    assert not reported - {planted}, f"safe look-alike reported too: {reported}"


def test_detect_code_matches_detect_on_the_same_source(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    by_file = [(f.cwe, f.line_start) for f in detect(case, CONFIG)]
    by_string = [(f.cwe, f.line_start) for f in detect_code(case.code, case.case_id, CONFIG)]
    assert by_file == by_string


def test_detect_is_quiet_on_harmless_code(tmp_path):
    case = make_case(tmp_path, code="def add(a, b):\n    return a + b\n")
    assert detect(case, CONFIG) == []


# --- parameterized SQL (bandit's B608 reports it anyway) ---------------------
# B608 matches a string that looks like SQL and is built at all, so it reports a
# correct query exactly as loudly as an injectable one. ../references/CWE-89.md:
# interpolating a fixed identifier is not interpolating a value.

TABLE_CONST_SQL = """\
TABLE = "items"
def count(conn, location):
    query = f"SELECT COUNT(*) FROM {TABLE} WHERE location = ?"
    return conn.execute(query, (location,)).fetchone()
"""

INJECTABLE_SQL = """\
TABLE = "items"
def find(conn, name):
    query = f"SELECT * FROM {TABLE} WHERE name = '{name}'"
    return conn.execute(query).fetchall()
"""


def test_sql_interpolating_only_a_constant_is_dropped(tmp_path):
    """The table name comes from a module constant; the value is bound."""
    case = make_case(tmp_path, code=TABLE_CONST_SQL)
    assert "CWE-89" not in {f.cwe for f in detect(case, CONFIG)}


def test_sql_interpolating_a_value_is_kept(tmp_path):
    case = make_case(tmp_path, code=INJECTABLE_SQL)
    assert "CWE-89" in {f.cwe for f in detect(case, CONFIG)}


def test_fully_static_query_is_dropped(tmp_path):
    code = ('def all_rows(conn):\n'
            '    return conn.execute("SELECT id, name FROM items").fetchall()\n')
    case = make_case(tmp_path, code=code)
    assert "CWE-89" not in {f.cwe for f in detect(case, CONFIG)}


def test_concatenated_value_is_kept(tmp_path):
    code = ('def find(conn, status):\n'
            '    q = "SELECT id FROM tickets WHERE status = \'" + status + "\'"\n'
            '    return conn.execute(q).fetchall()\n')
    case = make_case(tmp_path, code=code)
    assert "CWE-89" in {f.cwe for f in detect(case, CONFIG)}


def test_query_built_on_an_earlier_line_is_still_kept(tmp_path):
    """The verdict has to carry from where the string was built to where it runs."""
    const, dynamic = _constant_only_sql(INJECTABLE_SQL)
    assert dynamic, "the f-string interpolating `name` must mark its line dynamic"


def test_interpolated_returns_the_dynamic_parts():
    import ast
    node = ast.parse('f"a{b}c{d}"').body[0].value
    assert len(_interpolated(node)) == 2
    assert _interpolated(ast.parse('"plain"').body[0].value) is None


def test_mixed_span_fails_safe_towards_reporting():
    """A span with one constant-only and one dynamic line is kept."""
    finding = _finding_from_bandit({
        "issue_cwe": {"id": 89}, "line_range": [3, 4], "line_number": 3,
        "test_id": "B608", "issue_text": "hardcoded_sql_expressions",
    }, "c", CONFIG)
    assert not _is_parameterized_sql(finding, frozenset({3}), frozenset({4}))


def test_sql_filter_leaves_other_rules_alone():
    finding = _finding_from_bandit({
        "issue_cwe": {"id": 78}, "line_range": [3], "line_number": 3,
        "test_id": "B602", "issue_text": "shell=True",
    }, "c", CONFIG)
    assert not _is_parameterized_sql(finding, frozenset({3}), frozenset())


# --- scanning more than one file ---------------------------------------------

def test_detect_tree_scans_every_python_file(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text(INJECTABLE_SQL, encoding="utf-8")
    (tmp_path / "b.py").write_text(
        'import subprocess\ndef r(c):\n    return subprocess.getoutput("ls " + c)\n',
        encoding="utf-8")
    findings = detect_tree(tmp_path, CONFIG)
    assert {"CWE-89", "CWE-78"} <= {f.cwe for f in findings}
    assert {"pkg/a.py", "b.py"} == {f.case_id for f in findings}


def test_detect_tree_skips_virtualenvs_and_caches(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "evil.py").write_text(INJECTABLE_SQL, encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.py").write_text(INJECTABLE_SQL, encoding="utf-8")
    assert detect_tree(tmp_path, CONFIG) == []


def test_detect_tree_accepts_a_single_file(tmp_path):
    target = tmp_path / "one.py"
    target.write_text(INJECTABLE_SQL, encoding="utf-8")
    findings = detect_tree(target, CONFIG)
    assert findings and all(f.case_id == "one.py" for f in findings)


def test_detect_tree_is_quiet_on_a_clean_tree(tmp_path):
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert detect_tree(tmp_path, CONFIG) == []
