import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn } from 'child_process';

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
	outputChannel = vscode.window.createOutputChannel('AI Evaluator');
	context.subscriptions.push(outputChannel);

	const disposable = vscode.commands.registerCommand(
		'aiEvaluator.analyzeForVulnerabilities',
		() => analyzeForVulnerabilities(context)
	);

	context.subscriptions.push(disposable);
}

async function analyzeForVulnerabilities(context: vscode.ExtensionContext) {
	const editor = vscode.window.activeTextEditor;

	if (!editor) {
		vscode.window.showWarningMessage('AI Evaluator: Open a file to analyze first.');
		return;
	}

	if (editor.document.languageId !== 'python') {
		vscode.window.showWarningMessage('AI Evaluator: Only Python files are supported right now.');
		return;
	}

	if (editor.document.isDirty) {
		vscode.window.showWarningMessage('AI Evaluator: Save the file before analyzing - results reflect the file on disk.');
	}

	const workspaceFolder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
	const engineDir = workspaceFolder ? path.join(workspaceFolder.uri.fsPath, 'Engine') : undefined;
	const fixerScript = engineDir ? path.join(engineDir, 'fixer.py') : undefined;

	if (!engineDir || !fixerScript || !fs.existsSync(fixerScript)) {
		vscode.window.showErrorMessage('AI Evaluator: Could not find Engine/fixer.py in this workspace.');
		return;
	}

	const pythonPath = resolvePythonExecutable(engineDir);
	const filePath = editor.document.uri.fsPath;

	outputChannel.clear();
	outputChannel.show(true);
	outputChannel.appendLine(`Running fixer.py on ${filePath}\n`);

	await vscode.window.withProgress(
		{
			location: vscode.ProgressLocation.Notification,
			title: 'AI Evaluator: Analyzing for vulnerabilities...',
			cancellable: false,
		},
		() =>
			new Promise<void>((resolve) => {
				const proc = spawn(pythonPath, ['fixer.py', filePath], { cwd: engineDir });

				proc.stdout.on('data', (chunk: Buffer) => outputChannel.append(chunk.toString()));
				proc.stderr.on('data', (chunk: Buffer) => outputChannel.append(chunk.toString()));

				proc.on('error', (err) => {
					outputChannel.appendLine(`\n[error] Failed to start fixer.py: ${err.message}`);
					vscode.window.showErrorMessage(
						`AI Evaluator: Failed to run fixer.py (${err.message}). See Engine/README.md for setup.`
					);
					resolve();
				});

				proc.on('close', (code) => {
					if (code === 0) {
						vscode.window.showInformationMessage('AI Evaluator: Analysis complete. See the "AI Evaluator" output panel.');
					} else {
						vscode.window.showErrorMessage(`AI Evaluator: fixer.py exited with code ${code}. See the output panel for details.`);
					}
					resolve();
				});
			})
	);
}

function resolvePythonExecutable(engineDir: string): string {
	const venvPython = process.platform === 'win32'
		? path.join(engineDir, '.venv', 'Scripts', 'python.exe')
		: path.join(engineDir, '.venv', 'bin', 'python');

	return fs.existsSync(venvPython) ? venvPython : 'python3';
}

export function deactivate() {}
