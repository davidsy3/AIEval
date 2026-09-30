"""Small, offline AST checks. These identify risky patterns, not proven exploits."""
import ast
import re


def analyze_local(code: str, path: str) -> str:
    tree = ast.parse(code, filename=path)
    findings = []
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        return ""

    def add(node, title, cwe, severity, description, recommendation):
        findings.append((node.lineno, title, cwe, severity, description, recommendation))

    def formatted(node):
        return (isinstance(node, ast.JoinedStr)
                or isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
                or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format")

    # Resolve simple, preceding assignments within the current function/module only.
    def resolve(node, bindings):
        seen = set()
        while isinstance(node, ast.Name) and node.id in bindings and node.id not in seen:
            seen.add(node.id)
            node = bindings[node.id]
        return node

    class Checks(ast.NodeVisitor):
        def __init__(self):
            self.bindings = {}

        def visit_FunctionDef(self, node):
            previous = self.bindings
            self.bindings = {}
            for statement in node.body:
                self.visit(statement)
            self.bindings = previous

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

        def assignment(self, targets, value, node):
            for target in targets:
                target_name = name(target)
                if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                    secret_name = re.search(r'(?:password|passwd|secret|token|api_?key|access_key|(?:^|_)pass$)', target_name, re.I)
                    credential_url = re.search(r'^[a-z][a-z0-9+.-]*://[^/\s:]+:[^/\s@]+@', value.value, re.I)
                    if secret_name or credential_url:
                        add(node, 'Hard-coded credentials', 'CWE-798', 'HIGH',
                            f'{target_name} contains a literal credential or secret. This may expose credentials if the source is shared. Verify whether it is a test placeholder.',
                            'Load real credentials from an environment variable or secret store; rotate any exposed real credentials.')
                if isinstance(target, ast.Name):
                    self.bindings[target.id] = resolve(value, self.bindings)
            self.generic_visit(node)

        def visit_Assign(self, node):
            self.assignment(node.targets, node.value, node)

        def visit_AnnAssign(self, node):
            self.assignment([node.target], node.value, node)

        def visit_Call(self, node):
            called = name(node.func)
            first = resolve(node.args[0], self.bindings) if node.args else None
            if called.endswith(('.execute', '.executemany', '.executescript')) and first is not None and formatted(first):
                add(node, 'Potential SQL injection', 'CWE-89', 'HIGH',
                    'A database execution call receives a query built with string formatting or concatenation. This can permit SQL injection if any interpolated value is untrusted.',
                    'Use a constant SQL query with bound parameters instead of interpolating values.')
            shell = any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            if called in ('os.system', 'os.popen') or called in ('subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_call', 'subprocess.check_output') and shell:
                add(node, 'Potential OS command injection', 'CWE-78', 'HIGH',
                    'This call invokes a shell. If untrusted data reaches the command, it can execute additional commands. Review the command inputs.',
                    'Pass a list of arguments to subprocess with shell=False and validate untrusted arguments.')
            weak_hash = called in ('hashlib.md5', 'hashlib.sha1') or called == 'hashlib.new' and isinstance(first, ast.Constant) and str(first.value).lower() in ('md5', 'sha1')
            if weak_hash:
                add(node, 'Weak cryptographic hash', 'CWE-327', 'MEDIUM',
                    'MD5 or SHA-1 is used. These hashes are unsuitable for collision-resistant security checks; verify whether this usage is security-sensitive.',
                    'Use SHA-256 or stronger for integrity checks; use a dedicated password hashing algorithm for passwords.')
            if called in ('open', 'io.open') and isinstance(first, ast.Call) and name(first.func) == 'os.path.join' and any(not isinstance(arg, ast.Constant) for arg in first.args):
                add(node, 'Potential path traversal', 'CWE-22', 'MEDIUM',
                    'A file is opened using a joined path with variable components. If these components are untrusted, they may escape the intended directory.',
                    'Resolve the path and verify it stays inside the allowed base directory before opening it.')
            self.generic_visit(node)

    Checks().visit(tree)
    findings.sort(key=lambda item: item[0])
    section_a = []
    section_b = []
    for index, (line, title, cwe, severity, description, recommendation) in enumerate(findings, 1):
        section_a.append(f'{index}. {title} ({cwe}), line {line}; Severity: {severity}')
        section_b.append(f'{index}. {description}\nRecommendation: {recommendation}')
    return '\n\n'.join([
        'A. FINDINGS\n' + ('\n'.join(section_a) or 'NONE'),
        'B. EXPLANATIONS\n' + ('\n\n'.join(section_b) or 'No supported risky patterns detected.'),
        'C. COMPATIBILITY RISK\nLow — no source changes are generated by local checks.',
        'D. FIXED CODE\nNO CHANGES',
        'E. PROPOSE TO HUMAN\nLocal static checks only. Review findings to confirm exploitability. These checks do not prove that a file is secure and do not cover every vulnerability.',
    ])
