import type { LabelledField } from "./providers/types.js";

/** "Label: value" lines, e.g. "Date of birth: 14 March 2005". */
export function labelledLines(text: string): LabelledField[] {
  const fields: LabelledField[] = [];
  for (const m of text.matchAll(/^[ \t]*([A-Za-z][A-Za-z0-9 .'()/&_-]{0,47}?)[ \t]*:[ \t]*(\S[^\n\r]*)$/dgm)) {
    const label = m[1];
    const span = m.indices?.[2];
    if (label && span) fields.push({ label, start: span[0], end: span[1] });
  }
  return fields;
}

export interface CsvCell {
  row: number;
  columnIndex: number;
  start: number;
  end: number;
}

/** RFC 4180 tokenizer that records each cell's content span in the source text. */
export function parseCsvCells(text: string): CsvCell[] {
  const cells: CsvCell[] = [];
  let row = 1;
  let column = 0;
  let i = 0;
  const length = text.length;
  while (i <= length) {
    let start = i;
    let end: number;
    if (text[i] === '"') {
      start = i + 1;
      i += 1;
      while (i < length) {
        if (text[i] === '"') {
          if (text[i + 1] === '"') i += 2;
          else break;
        } else i += 1;
      }
      end = i;
      i += 1;
      while (i < length && text[i] !== "," && text[i] !== "\n" && text[i] !== "\r") i += 1;
    } else {
      while (i < length && text[i] !== "," && text[i] !== "\n" && text[i] !== "\r") i += 1;
      end = i;
    }
    cells.push({ row, columnIndex: column, start, end });
    if (i >= length) break;
    if (text[i] === ",") {
      column += 1;
      i += 1;
    } else {
      if (text[i] === "\r" && text[i + 1] === "\n") i += 1;
      i += 1;
      row += 1;
      column = 0;
      if (i >= length) break;
    }
  }
  return cells;
}

export interface CsvLayout {
  headers: string[];
  cells: CsvCell[];
  fields: LabelledField[];
}

export function csvLayout(text: string): CsvLayout {
  const cells = parseCsvCells(text);
  const headers = cells
    .filter((cell) => cell.row === 1)
    .map((cell) => text.slice(cell.start, cell.end).replace(/""/g, '"').trim());
  const fields = cells
    .filter((cell) => cell.row > 1 && cell.end > cell.start)
    .map((cell) => ({
      label: headers[cell.columnIndex] ?? `Column ${cell.columnIndex + 1}`,
      start: cell.start,
      end: cell.end,
    }));
  return { headers, cells, fields };
}

/** Spreadsheet-style column letter: 0 -> A, 26 -> AA. */
export function columnLetter(index: number): string {
  let n = index + 1;
  let letters = "";
  while (n > 0) {
    const rem = (n - 1) % 26;
    letters = String.fromCharCode(65 + rem) + letters;
    n = Math.floor((n - 1) / 26);
  }
  return letters;
}
