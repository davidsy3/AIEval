import { randomBytes } from 'crypto';

export interface SecurityFinding {
	type: string;
	severity?: string;
	file: string;
	line?: number;
	endLine?: number;
	description: string;
	recommendation?: string;
}

export type Decision = 'accepted' | 'declined';

// One suggested change as shown in the Webview; the user accepts or declines each one.
export interface ChangeView {
	id: string;
	line: number;
	endLine?: number;
	removed: string[];
	added: string[];
	decision?: Decision;
	related: string[];
}

// Adapt the engine's existing A–E text report; compatibility risk is not severity.
export function parseFindings(report: string, file: string): SecurityFinding[] {
	const text = report.replace(/^\s*#{1,6}\s*/gm, '').replace(/\*\*/g, '');
	const sections = /^A\. FINDINGS\s*\n([\s\S]*?)^B\. EXPLANATIONS\s*\n([\s\S]*?)^C\. COMPATIBILITY RISK\b/m.exec(text);
	if (!sections || !/^D\. FIXED CODE\b/m.test(text) || !/^E\. PROPOSE TO HUMAN\b/m.test(text)) {
		throw new Error('The Python analysis engine returned an invalid or incomplete report. See the output panel for details.');
	}
	if (/^(?:NONE|NO TARGET VULNERABILITIES FOUND)[.!]?$/i.test(sections[1].trim())) { return []; }
	const entries = (value: string) => value.trim().split(/\n(?=\s*\d+[.)]\s)/);
	const explanations = entries(sections[2]);
	const findings = entries(sections[1]);
	if (!findings.length || findings.some(value => !/^\d+[.)]\s/.test(value.trim()) || !/CWE-\d+/i.test(value))) {
		throw new Error('The Python analysis engine returned findings that could not be read. See the output panel for details.');
	}
	return findings.map((value, index) => {
		const detail = value.replace(/^\s*\d+[.)]\s*/, '').trim();
		const explanation = explanations.find(item => new RegExp(`^\\s*${index + 1}[.)]\\s`).test(item));
		const description = explanation?.replace(/^\s*\d+[.)]\s*/, '').trim() || detail;
		const line = /\blines?\s*[:#]?\s*(\d+)(?:\s*[-–]\s*(\d+))?/i.exec(detail);
		return {
			type: detail.split('\n')[0], file,
			line: line ? Number(line[1]) : undefined,
			endLine: line?.[2] ? Number(line[2]) : undefined,
			severity: /\bseverity\s*[:=-]\s*(CRITICAL|HIGH|MEDIUM|LOW)\b/i.exec(detail + '\n' + description)?.[1].toUpperCase(),
			description,
			recommendation: /(?:Recommendation|Recommended fix)\s*:\s*([\s\S]+)/i.exec(description)?.[1].trim(),
		};
	});
}

// Section C rates how likely the suggested rewrite changes behavior; shown beside the apply button.
export function parseCompatibilityRisk(report: string): string | undefined {
	const text = report.replace(/^\s*#{1,6}\s*/gm, '').replace(/\*\*/g, '');
	const risk = /^C\. COMPATIBILITY RISK\b\s*[:\-–—]?\s*(Low|Medium|High)\b/im.exec(text)?.[1];
	return risk && risk[0].toUpperCase() + risk.slice(1).toLowerCase();
}

export function webviewHtml(): string {
	const nonce = randomBytes(16).toString('hex');
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
<title>AI Evaluator</title><style nonce="${nonce}">
body { background: var(--vscode-editor-background); color: var(--vscode-foreground); font-family: var(--vscode-font-family); font-size: var(--vscode-font-size); padding: 24px; }
main { max-width: 780px; margin: auto; } h1 { font-size: 24px; margin-bottom: 8px; } h2 { font-size: 16px; margin-top: 32px; }
p { line-height: 1.6; } .muted, .location { color: var(--vscode-descriptionForeground); } .label { display: block; margin: 24px 0 8px; font-weight: 600; }
#file, #analyzed-file, .card { overflow-wrap: anywhere; } button { margin-top: 20px; padding: 9px 16px; border: 1px solid var(--vscode-button-border, transparent); border-radius: 4px; background: var(--vscode-button-background); color: var(--vscode-button-foreground); cursor: pointer; font: inherit; }
button:hover { background: var(--vscode-button-hoverBackground); } button:disabled { opacity: .6; cursor: wait; } button:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 3px; }
.card { border: 1px solid var(--vscode-panel-border, var(--vscode-input-border)); border-radius: 5px; padding: 18px; margin-top: 14px; }
.card header { display: flex; gap: 12px; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; } h3 { font-size: 14px; margin: 0; } .badge { font-size: 11px; border: 1px solid currentColor; border-radius: 4px; padding: 3px 6px; }
.CRITICAL, .HIGH, .error { color: var(--vscode-errorForeground); } .MEDIUM { color: var(--vscode-editorWarning-foreground); } .LOW { color: var(--vscode-editorInfo-foreground); } .detail { white-space: pre-wrap; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; } .actions button { margin-top: 8px; }
.secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); } .secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
.diff { margin: 12px 0 0; padding: 8px 0; max-height: 320px; overflow: auto; font-family: var(--vscode-editor-font-family); font-size: var(--vscode-editor-font-size); border-radius: 4px; background: var(--vscode-textCodeBlock-background); }
.diff div { padding: 0 10px; white-space: pre; } .diff .del { background: var(--vscode-diffEditor-removedLineBackground, var(--vscode-diffEditor-removedTextBackground)); } .diff .add { background: var(--vscode-diffEditor-insertedLineBackground, var(--vscode-diffEditor-insertedTextBackground)); }
.change.accepted { border-color: var(--vscode-testing-iconPassed, var(--vscode-focusBorder)); } .change.declined { opacity: .7; }
.status-accepted { color: var(--vscode-testing-iconPassed, inherit); } .status-declined { color: var(--vscode-descriptionForeground); }
button[aria-pressed="true"] { outline: 2px solid var(--vscode-focusBorder); outline-offset: 1px; }
@media (max-width: 400px) { body { padding: 12px; } }
</style></head><body><main><h1>AI Evaluator</h1><p class="muted">Analyze Python code for security vulnerabilities.</p>
<span class="label">Current File</span><div id="file">No file selected</div><button id="analyze">Analyze File</button>
<div id="analyzed" hidden><span class="label">File Analyzed</span><div id="analyzed-file"></div></div>
<h2>Security Findings</h2><section id="results" aria-live="polite"><p>Run an analysis to view security findings.</p></section></main>
<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
const button = document.getElementById('analyze');
const results = document.getElementById('results');
let focusKey;
function element(tag, text, className) { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; return node; }
button.addEventListener('click', () => { button.disabled = true; vscode.postMessage({ command: 'analyze' }); });
window.addEventListener('message', ({ data }) => {
 document.getElementById('file').textContent = data.file || 'No file selected';
 const analyzed = document.getElementById('analyzed-file'); analyzed.textContent = data.analyzedFile || ''; analyzed.title = data.analyzedPath || ''; document.getElementById('analyzed').hidden = !data.analyzedFile;
 button.disabled = data.busy; button.textContent = data.busy ? 'Analyzing...' : 'Analyze File';
 results.replaceChildren();
 if (data.busy) { results.append(element('p', 'Analysis is running...')); return; }
 if (data.error) { results.append(element('h3', data.errorTitle || 'Analysis failed', 'error'), element('p', data.error)); return; }
 if (!data.findings) { results.append(element('p', 'Run an analysis to view security findings.')); return; }
 if (data.note) results.append(element('p', data.note, 'muted'));
 if (!data.findings.length) { results.append(element('h3', '✓ No vulnerabilities detected'), element('p', 'The analyzer did not identify any supported security vulnerabilities in this file.')); return; }
 results.append(element('p', data.findings.length + (data.findings.length === 1 ? ' vulnerability found' : ' vulnerabilities found')));
 if (data.canApply && data.changes) {
  const changes = data.changes, decided = changes.filter(c => c.decision).length, accepted = changes.filter(c => c.decision === 'accepted').length;
  const fix = element('section', '', 'card');
  fix.append(element('h3', 'Suggested Changes'), element('p', 'Review each change and accept or decline it. Only accepted changes are applied to ' + data.analyzedFile + ', and nothing changes until you apply.', 'muted'));
  if (data.risk) fix.append(element('p', 'Compatibility risk: ' + data.risk, data.risk.toUpperCase()));
  fix.append(element('p', decided + ' of ' + changes.length + ' reviewed · ' + accepted + ' accepted'));
  changes.forEach((change, index) => {
   const card = element('article', '', 'card change' + (change.decision ? ' ' + change.decision : '')); const header = element('header', '');
   const where = change.removed.length ? 'Line' + (change.endLine > change.line ? 's ' + change.line + '-' + change.endLine : ' ' + change.line) : 'Insert before line ' + change.line;
   header.append(element('h3', 'Change ' + (index + 1) + ' of ' + changes.length + ' · ' + where),
    element('span', change.decision === 'accepted' ? 'Accepted' : change.decision === 'declined' ? 'Declined' : 'Pending', 'badge status-' + (change.decision || 'pending')));
   card.append(header);
   if (change.related.length) card.append(element('p', 'Related: ' + change.related.join('; '), 'location'));
   const diff = element('div', '', 'diff');
   for (const line of change.removed) diff.append(element('div', '- ' + line, 'del'));
   for (const line of change.added) diff.append(element('div', '+ ' + line, 'add'));
   card.append(diff);
   const actions = element('div', '', 'actions');
   const choice = (label, decision, className) => {
    const b = element('button', label, className); b.dataset.focus = change.id + decision; b.setAttribute('aria-pressed', String(change.decision === decision));
    b.addEventListener('click', () => { focusKey = b.dataset.focus; vscode.postMessage({ command: 'decide', id: change.id, decision: change.decision === decision ? undefined : decision }); });
    return b;
   };
   const show = element('button', 'Show in Diff', 'secondary');
   show.addEventListener('click', () => vscode.postMessage({ command: 'review', id: change.id }));
   actions.append(choice('Accept', 'accepted'), choice('Decline', 'declined', 'secondary'), show); card.append(actions); fix.append(card);
  });
  const actions = element('div', '', 'actions');
  const review = element('button', 'Review All Changes', 'secondary');
  review.addEventListener('click', () => vscode.postMessage({ command: 'review' }));
  const apply = element('button', decided < changes.length ? 'Review all changes to apply' : accepted ? 'Apply ' + accepted + ' Accepted Change' + (accepted === 1 ? '' : 's') : 'Finish Review (no changes)');
  apply.disabled = decided < changes.length;
  apply.addEventListener('click', () => { apply.disabled = true; vscode.postMessage({ command: 'apply' }); });
  actions.append(review, apply); fix.append(actions); results.append(fix);
 }
 if (data.fixMessage) results.append(element('p', data.fixMessage));
 // Re-rendering replaces the buttons; keep keyboard focus on the one just used.
 if (focusKey) { results.querySelector('[data-focus="' + CSS.escape(focusKey) + '"]')?.focus(); focusKey = undefined; }
 for (const finding of data.findings) {
  const card = element('article', '', 'card'); const header = element('header', '');
  const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(finding.severity) ? finding.severity : '';
  header.append(element('h3', finding.type), element('span', severity || 'Not specified', 'badge ' + severity));
  card.append(header, element('p', finding.file + (finding.line ? ':' + finding.line + (finding.endLine > finding.line ? '-' + finding.endLine : '') : ''), 'location'), element('p', finding.description, 'detail'));
  if (finding.recommendation) card.append(element('h3', 'Recommendation'), element('p', finding.recommendation, 'detail'));
  results.append(card);
 }
});
vscode.postMessage({ command: 'ready' });
</script></body></html>`;
}
