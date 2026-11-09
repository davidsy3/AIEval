import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn } from 'child_process';
import { ChangeView, Decision, parseCompatibilityRisk, parseFindings, SecurityFinding, webviewHtml } from './webview';
import { computeHunks, Hunk, hunkKey } from './diff';

let outputChannel: vscode.OutputChannel;
let diagnostics: vscode.DiagnosticCollection;
let panel: vscode.WebviewPanel | undefined;
let currentDocument: vscode.TextDocument | undefined;
let state: { file?: string; analyzedFile?: string; analyzedPath?: string; busy: boolean; findings?: SecurityFinding[]; error?: string; errorTitle?: string; note?: string; canApply?: boolean; risk?: string; fixMessage?: string; changes?: ChangeView[] } = { busy: false };
// The engine's fixed file for the last analysis, the source it was made from, its individual changes
// and the user's decision on each. Kept out of the Webview state.
let pendingFix: { path: string; original: string; fixedPath: string; hunks: Hunk[]; decisions: Map<string, Decision> } | undefined;
let applying = false;

function publish() {
	void panel?.webview.postMessage(state);
}

function openEvaluator(context: vscode.ExtensionContext) {
	if (panel) { panel.reveal(vscode.ViewColumn.Beside); return; }
	panel = vscode.window.createWebviewPanel('aiEvaluator', 'AI Evaluator', vscode.ViewColumn.Beside, {
		enableScripts: true, localResourceRoots: [],
	});
	panel.webview.onDidReceiveMessage(message => {
		if (message?.command === 'ready') { publish(); }
		if (message?.command === 'logs') { outputChannel.show(true); }
		if (message?.command === 'analyze') { void analyzeForVulnerabilities(context); }
		if (message?.command === 'review') { void reviewSuggestedChanges(typeof message.id === 'string' ? message.id : undefined); }
		if (message?.command === 'decide') { decideChange(message.id, message.decision); }
		if (message?.command === 'apply') { void applySuggestedChanges(); }
	}, undefined, context.subscriptions);
	panel.onDidDispose(() => { panel = undefined; }, undefined, context.subscriptions);
	context.subscriptions.push(panel);
	panel.webview.html = webviewHtml();
}

export function activate(context: vscode.ExtensionContext) {
	outputChannel = vscode.window.createOutputChannel('AI Evaluator');
	context.subscriptions.push(outputChannel);
	diagnostics = vscode.languages.createDiagnosticCollection('aiEvaluator');
	context.subscriptions.push(diagnostics, vscode.workspace.onDidChangeTextDocument(updateDiagnosticsForEdit),
		// Edits made to the suggested code in the Review Changes diff change the list of changes to decide on.
		vscode.workspace.onDidChangeTextDocument(event => {
			if (pendingFix && !applying && samePath(event.document.uri.fsPath, pendingFix.fixedPath)) {
				refreshChanges(event.document.getText());
				publish();
			}
		}));

	const disposable = vscode.commands.registerCommand(
		'aiEvaluator.analyzeForVulnerabilities',
		() => analyzeForVulnerabilities(context)
	);

	currentDocument = vscode.window.activeTextEditor?.document;
	state.file = currentDocument && path.basename(currentDocument.uri.fsPath);
	context.subscriptions.push(disposable,
		vscode.commands.registerCommand('aiEvaluator.open', () => openEvaluator(context)),
		vscode.window.onDidChangeActiveTextEditor(editor => {
			// A focused Webview has no active text editor. Keep its last target.
			if (!editor) { return; }
			currentDocument = editor.document;
			if (!state.busy) {
				// Keep the last analysis; only the file the next run will target changes.
				state = { ...state, file: path.basename(currentDocument.uri.fsPath) };
				publish();
			}
		}),
		vscode.workspace.onDidCloseTextDocument(document => {
			if (currentDocument === document) { currentDocument = undefined; }
		})
	);

	// Empty provider so the view renders its viewsWelcome button rather than a "no data provider" error.
	const emptyProvider: vscode.TreeDataProvider<vscode.TreeItem> = {
		getTreeItem: (element) => element,
		getChildren: () => [],
	};
	context.subscriptions.push(vscode.window.registerTreeDataProvider('aiEvaluator.analyze', emptyProvider));

	if (context.extensionMode === vscode.ExtensionMode.Development) {
		void openDevTestFile(context);
	}
}

async function openDevTestFile(context: vscode.ExtensionContext): Promise<void> {
	const testFile = path.join(context.extensionPath, 'Engine', 'testfile.py');
	if (!fs.existsSync(testFile)) {
		return;
	}

	const doc = await vscode.workspace.openTextDocument(testFile);
	await vscode.window.showTextDocument(doc);
}

async function analyzeForVulnerabilities(context: vscode.ExtensionContext) {
	if (state.busy || applying) { publish(); return; }
	pendingFix = undefined;
	const document = vscode.window.activeTextEditor?.document || currentDocument;
	openEvaluator(context);
	const fail = (message: string, title = 'Unable to analyze file') => {
		pendingFix = undefined;
		state = { busy: false, file: document && path.basename(document.uri.fsPath), analyzedFile: document && path.basename(document.uri.fsPath), analyzedPath: document?.uri.fsPath, error: message, errorTitle: title };
		publish();
	};

	if (!document || document.isClosed) {
		fail('Open a Python file before running AI Evaluator.');
		vscode.window.showWarningMessage('AI Evaluator: Open a file to analyze first.');
		return;
	}

	if (document.languageId !== 'python') {
		fail('Only Python files are supported. Open a Python file before running AI Evaluator.');
		vscode.window.showWarningMessage('AI Evaluator: Only Python files are supported right now.');
		return;
	}

	if (document.isUntitled || document.uri.scheme !== 'file') {
		fail('Save the Python file to disk before analyzing.');
		return;
	}

	if (document.isDirty) {
		vscode.window.showWarningMessage('AI Evaluator: Save the file before analyzing - results reflect the file on disk.');
	}

	const engineDir = path.join(context.extensionPath, 'Engine');
	const fixerScript = path.join(engineDir, 'fixer.py');

	if (!fs.existsSync(fixerScript)) {
		fail(`Could not find fixer.py at ${fixerScript}`);
		vscode.window.showErrorMessage(`AI Evaluator: Could not find fixer.py at ${fixerScript}`);
		return;
	}

	const pythonPath = resolvePythonExecutable(engineDir);
	const filePath = document.uri.fsPath;

	state = { busy: true, file: path.basename(filePath), analyzedFile: path.basename(filePath), analyzedPath: filePath, note: document.isDirty ? 'Results reflect the saved file on disk; unsaved changes were not analyzed.' : undefined };
	publish();
	// A re-run replaces earlier results; a failed run leaves none.
	diagnostics.delete(document.uri);

	outputChannel.clear();

	outputChannel.appendLine(`Running fixer.py on ${filePath}\n`);

	try {
		await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: 'AI Evaluator: Analyzing for vulnerabilities...',
				cancellable: false,
			},
			() =>
				new Promise<void>((resolve) => {
					// The engine reads the file on disk; keep that version so a fix is never applied over later edits.
					const original = fs.readFileSync(filePath, 'utf8');
					const proc = spawn(pythonPath, ['fixer.py', filePath], { cwd: engineDir });

					let stderr = '';
					let failed = false;
					proc.stdout.on('data', (chunk: Buffer) => outputChannel.append(chunk.toString()));
					proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); outputChannel.append(chunk.toString()); });

					proc.on('error', (err) => {
						failed = true;
						fail(`Failed to run fixer.py (${err.message}). See Engine/README.md for setup.`, 'Analysis failed');
						outputChannel.appendLine(`\n[error] Failed to start fixer.py: ${err.message}`);
						vscode.window.showErrorMessage(
							`AI Evaluator: Failed to run fixer.py (${err.message}). See Engine/README.md for setup.`
						);
						resolve();
					});

					proc.on('close', (code) => {
						if (failed) { resolve(); return; }
						if (code === 0) {
							try {
								// Read the report the engine already saves, avoiding its echoed source code.
								const reportPath = /^\[saved\] Report: (.+)$/m.exec(stderr)?.[1].trim();
								if (!reportPath || !samePath(path.dirname(path.resolve(reportPath)), path.join(engineDir, 'output')) || stderr.includes('[warning]')) {
									throw new Error('The Python analysis engine returned an invalid or incomplete report. See the output panel for details.');
								}
								const report = fs.readFileSync(reportPath, 'utf8');
								state.findings = parseFindings(report, path.basename(filePath));
								showDiagnostics(document, state.findings);
								// Offer the engine's fixed file for the analyzed file only; the user decides whether to apply it.
								const fixedPath = /^\[saved\] Fixed code: (.+)$/m.exec(stderr)?.[1].trim();
								if (fixedPath && state.findings.length) {
									if (samePath(path.dirname(path.resolve(fixedPath)), path.join(engineDir, 'output')) && !stderr.includes('[notice] Line tags leaked')) {
										pendingFix = { path: filePath, original, fixedPath, hunks: [], decisions: new Map() };
										refreshChanges(fs.readFileSync(fixedPath, 'utf8'));
										if (pendingFix.hunks.length) {
											state.risk = parseCompatibilityRisk(report);
										} else {
											pendingFix = undefined;
											state.note = [state.note, 'The suggested fix does not change the file.'].filter(Boolean).join(' ');
										}
									} else {
										state.note = [state.note, 'The suggested fix could not be verified, so it cannot be applied automatically.'].filter(Boolean).join(' ');
									}
								}
								const mode = /^\[mode\] (.+)$/m.exec(stderr)?.[1];
								if (mode) { state.note = [state.note, mode].filter(Boolean).join(' '); }
							} catch (error) {
								fail(error instanceof Error ? error.message : String(error), 'Analysis failed');
								resolve(); return;
							}
							vscode.window.showInformationMessage('AI Evaluator: Analysis complete. See the AI Evaluator Webview.');
						} else {
							let message = `The Python analysis engine exited with code ${code}. Open View > Output and select AI Evaluator for details.`;
							if (/ModuleNotFoundError/.test(stderr)) {
								message = 'Python engine dependencies are missing. Create Engine/.venv and install Engine/requirements.txt using that environment. See Engine/README.md for setup.';
							} else if (/ANTHROPIC_API_KEY is not set|Invalid or missing API key|AuthenticationError/.test(stderr)) {
								message = 'An Anthropic API key is missing or invalid. Copy Engine/.env.example to Engine/.env and set ANTHROPIC_API_KEY to your key, then analyze again.';
							}
							fail(message, 'Analysis failed');
							vscode.window.showErrorMessage(`AI Evaluator: fixer.py exited with code ${code}. See the output panel for details.`);
						}
						resolve();
					});
				})
		);
	} catch (error) {
		fail(error instanceof Error ? error.message : String(error), 'Analysis failed');
	} finally {
		state.busy = false;
		publish();
	}
}

// Split the suggested code into individual changes, keeping decisions for changes that are still present.
function refreshChanges(fixedText: string) {
	if (!pendingFix) { return; }
	pendingFix.hunks = computeHunks(normalizeEol(pendingFix.original), normalizeEol(fixedText));
	const keys = new Set(pendingFix.hunks.map(hunkKey));
	for (const key of [...pendingFix.decisions.keys()]) {
		if (!keys.has(key)) { pendingFix.decisions.delete(key); }
	}
	syncChanges();
}

function syncChanges() {
	const fix = pendingFix;
	state.canApply = !!fix?.hunks.length;
	state.changes = fix?.hunks.map(hunk => {
		// 1-based original lines the change replaces; an insertion sits before line `first`.
		const first = hunk.start + 1, last = Math.max(hunk.end, first);
		return {
			id: hunkKey(hunk), line: first, endLine: hunk.end > hunk.start ? hunk.end : undefined,
			removed: hunk.removed, added: hunk.added, decision: fix.decisions.get(hunkKey(hunk)),
			related: (state.findings ?? []).filter(f => f.line && f.line <= last && (f.endLine ?? f.line) >= first).map(f => f.type),
		};
	});
}

function decideChange(id: unknown, decision: unknown) {
	if (pendingFix && !applying && typeof id === 'string' && pendingFix.hunks.some(hunk => hunkKey(hunk) === id)) {
		if (decision === 'accepted' || decision === 'declined') { pendingFix.decisions.set(id, decision); }
		else { pendingFix.decisions.delete(id); }
		state.fixMessage = undefined;
		syncChanges();
	}
	publish();
}

// Open the full diff, optionally scrolled to one change.
async function reviewSuggestedChanges(id?: string) {
	if (!pendingFix) { publish(); return; }
	const hunk = id ? pendingFix.hunks.find(item => hunkKey(item) === id) : undefined;
	const options: vscode.TextDocumentShowOptions = { viewColumn: vscode.ViewColumn.One };
	if (hunk) { options.selection = new vscode.Range(hunk.fixedStart, 0, hunk.fixedStart + Math.max(hunk.added.length - 1, 0), 0); }
	await vscode.commands.executeCommand('vscode.diff', vscode.Uri.file(pendingFix.path), vscode.Uri.file(pendingFix.fixedPath),
		`${path.basename(pendingFix.path)} ↔ Suggested Changes`, options);
}

// Apply only the changes the user accepted. Runs only when the user clicks Apply after deciding on every change.
async function applySuggestedChanges() {
	const fix = pendingFix;
	if (!fix || state.busy || applying) { publish(); return; }
	const name = path.basename(fix.path);
	if (fix.hunks.some(hunk => !fix.decisions.has(hunkKey(hunk)))) {
		state.fixMessage = 'Accept or decline every suggested change before applying.';
		publish(); return;
	}
	const accepted = fix.hunks.filter(hunk => fix.decisions.get(hunkKey(hunk)) === 'accepted');
	// Claim the fix so a repeated click cannot apply it twice.
	pendingFix = undefined;
	if (!accepted.length) {
		state = { ...state, canApply: false, changes: undefined, fixMessage: `All suggested changes were declined. ${name} was not changed.` };
		publish(); return;
	}
	applying = true;
	const failApply = (message: string) => {
		state = { ...state, fixMessage: message };
		vscode.window.showErrorMessage(`AI Evaluator: ${message}`);
	};
	try {
		const document = await vscode.workspace.openTextDocument(vscode.Uri.file(fix.path));
		if (normalizeEol(document.getText()) !== normalizeEol(fix.original)) {
			state.canApply = false;
			state.changes = undefined;
			failApply(`${name} changed after it was analyzed. Analyze it again before applying suggested changes.`);
			return;
		}
		// One edit per accepted change, so findings on untouched lines keep their diagnostics.
		const edit = new vscode.WorkspaceEdit();
		for (const hunk of accepted) { edit.replace(document.uri, ...hunkEdit(document, hunk)); }
		if (!await vscode.workspace.applyEdit(edit)) {
			pendingFix = fix;
			failApply(`Could not apply suggested changes to ${name}.`);
			return;
		}
		const saved = await document.save();
		const count = `${accepted.length} of ${fix.hunks.length} suggested change${fix.hunks.length === 1 ? '' : 's'}`;
		state = { ...state, canApply: false, changes: undefined, fixMessage: saved
			? `Applied ${count} to ${name}. Analyze the file again to verify the fix, or use Undo in the editor to revert.`
			: `Applied ${count} to ${name}, but the file could not be saved. Save it to keep the changes.` };
		vscode.window.showInformationMessage(`AI Evaluator: Applied ${count} to ${name}.`);
	} catch (error) {
		pendingFix = fix;
		failApply(error instanceof Error ? error.message : String(error));
	} finally {
		applying = false;
		publish();
	}
}

// The document range and replacement text for one change. The document matches the analyzed source line for line.
function hunkEdit(document: vscode.TextDocument, hunk: Hunk): [vscode.Range, string] {
	const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';
	const docEnd = document.lineAt(document.lineCount - 1).range.end;
	if (hunk.end < document.lineCount) {
		return [new vscode.Range(hunk.start, 0, hunk.end, 0), hunk.added.map(line => line + eol).join('')];
	}
	if (hunk.start === hunk.end) { return [new vscode.Range(docEnd, docEnd), eol + hunk.added.join(eol)]; }
	if (hunk.added.length) { return [new vscode.Range(new vscode.Position(hunk.start, 0), docEnd), hunk.added.join(eol)]; }
	// Removing the last lines also removes the line break before them.
	const from = hunk.start > 0 ? document.lineAt(hunk.start - 1).range.end : new vscode.Position(0, 0);
	return [new vscode.Range(from, docEnd), ''];
}

// VS Code reports one line ending per document and drops a UTF-8 BOM; compare and write text without either.
function normalizeEol(text: string): string {
	return text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
}

function showDiagnostics(document: vscode.TextDocument, findings: SecurityFinding[]) {
	const items = findings.flatMap(finding => {
		// Report lines are 1-based; skip findings without a usable line.
		if (!finding.line || finding.line > document.lineCount) { return []; }
		// Clamp ranges that end before they start or past the end of the file.
		const endLine = Math.min(Math.max(finding.endLine ?? finding.line, finding.line), document.lineCount);
		const first = document.lineAt(finding.line - 1);
		const last = document.lineAt(endLine - 1);
		const range = new vscode.Range(first.lineNumber, first.firstNonWhitespaceCharacterIndex, last.lineNumber, last.range.end.character);
		const diagnostic = new vscode.Diagnostic(range, `${finding.type}\n\n${finding.description}`, vscode.DiagnosticSeverity.Warning);
		diagnostic.source = 'NerdGoose';
		return [diagnostic];
	});
	diagnostics.set(document.uri, items);
}

// Drop findings on edited lines and move the rest with inserted or deleted lines.
function updateDiagnosticsForEdit(event: vscode.TextDocumentChangeEvent) {
	let items = diagnostics.get(event.document.uri);
	if (!items?.length || !event.contentChanges.length) { return; }

	// Change ranges refer to the document before the edit, so apply them bottom-up.
	const changes = [...event.contentChanges].sort((a, b) => b.range.start.compareTo(a.range.start));
	for (const change of changes) {
		const { start, end } = change.range;
		const delta = change.text.split('\n').length - 1 - (end.line - start.line);
		items = items.flatMap(item => {
			if (item.range.end.line < start.line) { return [item]; }
			// The edit touches at least one line of this finding's range.
			if (item.range.start.line <= end.line) { return []; }
			if (delta === 0) { return [item]; }
			const moved = new vscode.Diagnostic(
				new vscode.Range(item.range.start.translate(delta), item.range.end.translate(delta)),
				item.message, item.severity);
			moved.source = item.source;
			return [moved];
		});
	}
	diagnostics.set(event.document.uri, items);
}

// Windows paths are case-insensitive, and VS Code reports the drive letter in lowercase while Python uses uppercase.
function samePath(a: string, b: string): boolean {
	return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function resolvePythonExecutable(engineDir: string): string {
	const venvPython = process.platform === 'win32'
		? path.join(engineDir, '.venv', 'Scripts', 'python.exe')
		: path.join(engineDir, '.venv', 'bin', 'python');

	return fs.existsSync(venvPython) ? venvPython : 'python3';
}

export function deactivate() {}
