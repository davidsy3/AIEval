// A contiguous change between the analyzed file and the engine's fixed file.
export interface Hunk {
	// Replaced range in the original, as 0-based line indexes [start, end).
	start: number;
	end: number;
	// First line of the replacement in the fixed file (0-based).
	fixedStart: number;
	removed: string[];
	added: string[];
}

// Above this many cells the LCS table is too large; the differing middle becomes one change.
const MAX_CELLS = 25_000_000;

// Split two texts (LF line endings) into the smallest set of independent line changes.
export function computeHunks(original: string, fixed: string): Hunk[] {
	const a = original.split('\n');
	const b = fixed.split('\n');
	let prefix = 0;
	while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) { prefix++; }
	let suffix = 0;
	while (suffix < a.length - prefix && suffix < b.length - prefix && a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) { suffix++; }
	const n = a.length - prefix - suffix;
	const m = b.length - prefix - suffix;
	if (!n && !m) { return []; }
	if ((n + 1) * (m + 1) > MAX_CELLS) {
		return [{ start: prefix, end: prefix + n, fixedStart: prefix, removed: a.slice(prefix, prefix + n), added: b.slice(prefix, prefix + m) }];
	}

	// lcs[i][j] = length of the longest common subsequence of a[prefix+i..] and b[prefix+j..].
	const width = m + 1;
	const lcs = new Int32Array((n + 1) * width);
	for (let i = n - 1; i >= 0; i--) {
		for (let j = m - 1; j >= 0; j--) {
			lcs[i * width + j] = a[prefix + i] === b[prefix + j]
				? lcs[(i + 1) * width + j + 1] + 1
				: Math.max(lcs[(i + 1) * width + j], lcs[i * width + j + 1]);
		}
	}

	const hunks: Hunk[] = [];
	let current: Hunk | undefined;
	const close = () => { if (current) { hunks.push(current); current = undefined; } };
	let i = 0, j = 0;
	while (i < n || j < m) {
		if (i < n && j < m && a[prefix + i] === b[prefix + j]) { close(); i++; j++; continue; }
		current ??= { start: prefix + i, end: prefix + i, fixedStart: prefix + j, removed: [], added: [] };
		if (j < m && (i === n || lcs[i * width + j + 1] >= lcs[(i + 1) * width + j])) {
			current.added.push(b[prefix + j++]);
		} else {
			current.removed.push(a[prefix + i++]);
			current.end++;
		}
	}
	close();
	return hunks;
}

// Rebuild the original with only the given hunks applied.
export function applyHunks(original: string, hunks: Hunk[]): string {
	const lines = original.split('\n');
	for (const hunk of [...hunks].sort((x, y) => y.start - x.start)) {
		lines.splice(hunk.start, hunk.end - hunk.start, ...hunk.added);
	}
	return lines.join('\n');
}

// Stable identity for a hunk so a decision survives recomputing hunks after the fixed file is edited.
export function hunkKey(hunk: Hunk): string {
	return JSON.stringify([hunk.start, hunk.removed, hunk.added]);
}
