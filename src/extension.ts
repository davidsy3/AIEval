import * as vscode from 'vscode';

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

	if (editor.document.isDirty) {
		vscode.window.showWarningMessage('AI Evaluator: Save the file before analyzing - results reflect the file on disk.');
	}
}

export function deactivate() {}
