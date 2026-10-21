// Built-in rule-based detector: regexes, checksums, label context and a
// small first-name dictionary. Needs no external service or key.

import type { CategoryKey } from "../categories.js";
import { luhnValid, verhoeffValid } from "../checksums.js";
import type { DetectContext, Detection, DetectionProvider, LabelledField } from "./types.js";

const MONTHS =
  "Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?";

const DATE_PATTERNS = [
  /\b\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)\d{2}\b/g,
  /\b(?:19|20)\d{2}[/.-](?:0?[1-9]|1[0-2])[/.-](?:0?[1-9]|[12]\d|3[01])\b/g,
  new RegExp(
    `\\b(?:0?[1-9]|[12]\\d|3[01])(?:st|nd|rd|th)?\\s+(?:${MONTHS})\\.?,?\\s+(?:19|20)\\d{2}\\b`,
    "gi",
  ),
  new RegExp(
    `\\b(?:${MONTHS})\\.?\\s+(?:0?[1-9]|[12]\\d|3[01])(?:st|nd|rd|th)?,?\\s+(?:19|20)\\d{2}\\b`,
    "gi",
  ),
];

const CONTEXT = {
  dob: /\b(?:d\.?\s?o\.?\s?b\.?|date\s+of\s+birth|birth\s*date|birth\s*day|born)\b/i,
  aadhaar: /\b(?:aadhaa?r|uid|uidai)\b/i,
  pan: /\bpan\b/i,
  bank: /\b(?:account|a\/c|acct|bank)\b/i,
  card: /\b(?:card|credit|debit|visa|mastercard|rupay|amex)\b/i,
  phone: /\b(?:phone|mobile|cell|tel(?:ephone)?|contact|whatsapp)\b/i,
  financial: /\b(?:income|salary|ctc|wages?|pay|earnings|net\s*worth|balance|loan|emi|fees?)\b/i,
};

const NAME_LABEL = /\bname\b/i;
const NON_PERSON_NAME_LABEL =
  /\b(?:file|user|school|company|bank|product|course|project|college|institut\w*|organi[sz]ation|business|brand|host|domain|display|scheme|branch|program(?:me)?|award|event|account\s*type|street|city|village|district|state|country)\s*name\b/i;
const ADDRESS_LABEL = /\baddress\b/i;
const NON_POSTAL_ADDRESS_LABEL = /\b(?:e-?mail|ip|mac|web|url|wallet)\b/i;
const STUDENT_LABEL =
  /\b(?:roll|student|enrol{1,2}ment|admission|application|registration|candidate|hall\s*ticket|exam(?:ination)?)\b/i;
const REFERENCE_LABEL =
  /\b(?:employee|customer|member|patient|policy|client|ticket|reference|ref|staff)\b/i;
const GOVERNMENT_LABEL = /\b(?:passport|licen[cs]e|voter|ssn|social\s+security)\b/i;
const ID_WORD = /\b(?:id|no|number|num|code)\b|#/i;

const NAME_WORD = /^(?:\p{Lu}[\p{L}'’-]*\.?)$/u;
const NAME_PARTICLES = new Set(["de", "da", "van", "von", "bin", "binti", "al", "le", "la", "del"]);

const FIRST_NAMES = new Set(
  (
    "aarav aditi aditya akash akshay alok amit amita amol ananya anil anita anjali ankit anu anup " +
    "arjun aruna arun asha ashok bhavna deepa deepak devika dinesh divya farhan fatima gaurav geeta " +
    "harish isha ishaan jaya karan kavita kiran krishna kunal lakshmi lata madhu mahesh manish " +
    "meena meera mohan mohit nandini naveen neha nikhil nisha pallavi pooja prakash pranav " +
    "priya priyanka rahul raj rajesh rakesh ramesh ravi riya rohan rohit sachin sanjay sara " +
    "saurabh seema shalini shreya simran sneha sonia sunil sunita suresh swati tanvi uma varun " +
    "vijay vikram vinod vivek yash zara " +
    "james john robert michael william david richard joseph thomas charles mary patricia jennifer " +
    "linda elizabeth barbara susan jessica sarah karen emily emma olivia sophia daniel matthew " +
    "andrew peter paul mark george laura anna maria"
  ).split(/\s+/),
);

const NOT_A_SURNAME = new Set(
  (
    "lane road street avenue nagar colony school university college government senior secondary " +
    "class award merit india bank limited ltd pvt inc company department office hospital " +
    "january february march april may june july august september october november december " +
    "monday tuesday wednesday thursday friday saturday sunday the and of for application " +
    "statement purpose declaration"
  ).split(/\s+/),
);

/** Binary search for the labelled field containing an offset. */
function fieldAt(fields: LabelledField[], offset: number): LabelledField | undefined {
  let low = 0;
  let high = fields.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const field = fields[mid]!;
    if (offset < field.start) high = mid - 1;
    else if (offset >= field.end) low = mid + 1;
    else return field;
  }
  return undefined;
}

function contextBefore(text: string, fields: LabelledField[], start: number, window = 48): string {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const local = text.slice(Math.max(lineStart, start - window), start);
  const field = fieldAt(fields, start);
  return field ? `${field.label} ${local}` : local;
}

function digitsOf(value: string): string {
  return value.replace(/\D/g, "");
}

/** Trim a field value and cut it at the first separator; returns absolute offsets. */
function cleanFieldValue(
  text: string,
  field: LabelledField,
  cut?: RegExp,
): { start: number; end: number; value: string } | null {
  const raw = text.slice(field.start, field.end);
  const leading = raw.length - raw.trimStart().length;
  let value = raw.trim();
  if (cut) {
    const match = cut.exec(value);
    if (match) value = value.slice(0, match.index).trimEnd();
  }
  value = value.replace(/^["']|["']$/g, "");
  if (!value) return null;
  const start = field.start + raw.indexOf(value, leading > 0 ? leading - 1 : 0);
  return { start, end: start + value.length, value };
}

function isPlausibleName(value: string): boolean {
  const words = value.split(/\s+/);
  if (words.length < 1 || words.length > 5) return false;
  if (!words.some((word) => NAME_WORD.test(word))) return false;
  return words.every((word) => NAME_WORD.test(word) || NAME_PARTICLES.has(word));
}

function wordBoundaryAt(text: string, start: number, end: number): boolean {
  const before = start > 0 ? text[start - 1]! : " ";
  const after = end < text.length ? text[end]! : " ";
  return !/[\p{L}\p{N}]/u.test(before) && !/[\p{L}\p{N}]/u.test(after);
}

export function detectWithRules(text: string, fields: LabelledField[]): Detection[] {
  const detections: Detection[] = [];
  const push = (start: number, end: number, category: CategoryKey, confidence: number) => {
    if (end > start) {
      detections.push({ start, end, category, confidence, provider: "rules" });
    }
  };
  const ctxAt = (start: number) => contextBefore(text, fields, start);

  for (const m of text.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)) {
    push(m.index, m.index + m[0].length, "EMAIL", 0.97);
  }

  for (const m of text.matchAll(/(?<![\w+])(?:(?:\+|00)91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/g)) {
    push(m.index, m.index + m[0].length, "PHONE", 0.9);
  }
  for (const m of text.matchAll(/(?<![\w+])\+\d{1,3}(?:[\s.-]?\(?\d{1,4}\)?){2,5}(?!\d)/g)) {
    const count = digitsOf(m[0]).length;
    if (count >= 8 && count <= 15) push(m.index, m.index + m[0].length, "PHONE", 0.75);
  }
  for (const m of text.matchAll(/(?<!\d)\(\d{3}\)\s?\d{3}[\s.-]\d{4}(?!\d)/g)) {
    push(m.index, m.index + m[0].length, "PHONE", 0.7);
  }

  for (const m of text.matchAll(/(?<!\d[ -]?)[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![ -]?\d)/g)) {
    const digits = digitsOf(m[0]);
    const checksum = verhoeffValid(digits);
    const separated = m[1] !== "";
    const hasContext = CONTEXT.aadhaar.test(ctxAt(m.index));
    let confidence = 0;
    if (separated) confidence = checksum ? 0.95 : 0.7;
    else if (hasContext) confidence = checksum ? 0.92 : 0.75;
    else if (checksum) confidence = 0.6;
    if (confidence > 0) push(m.index, m.index + m[0].length, "AADHAAR", confidence);
  }

  for (const m of text.matchAll(/\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b/g)) {
    push(m.index, m.index + m[0].length, "PAN", CONTEXT.pan.test(ctxAt(m.index)) ? 0.95 : 0.9);
  }

  for (const m of text.matchAll(/(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)/g)) {
    const digits = digitsOf(m[0]);
    if (!luhnValid(digits) || /^(\d)\1+$/.test(digits)) continue;
    const context = ctxAt(m.index);
    if (CONTEXT.bank.test(context) && !CONTEXT.card.test(context)) continue;
    push(m.index, m.index + m[0].length, "CREDIT_CARD", 0.95);
  }

  for (const m of text.matchAll(/(?<!\d)\d{9,18}(?!\d)/g)) {
    if (CONTEXT.bank.test(ctxAt(m.index))) push(m.index, m.index + m[0].length, "BANK_ACCOUNT", 0.8);
  }
  for (const m of text.matchAll(/\b[A-Z]{4}0[A-Z0-9]{6}\b/g)) {
    push(m.index, m.index + m[0].length, "FINANCIAL", 0.8);
  }

  for (const m of text.matchAll(
    /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  )) {
    push(m.index, m.index + m[0].length, "IP_ADDRESS", 0.85);
  }
  for (const m of text.matchAll(/\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b/g)) {
    push(m.index, m.index + m[0].length, "IP_ADDRESS", 0.85);
  }

  for (const pattern of DATE_PATTERNS) {
    for (const m of text.matchAll(pattern)) {
      if (CONTEXT.dob.test(ctxAt(m.index))) {
        push(m.index, m.index + m[0].length, "DATE_OF_BIRTH", 0.88);
      }
    }
  }

  for (const m of text.matchAll(
    /(?:₹|\bINR|\bRs\.?)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:lakhs?|crores?|cr|k)\b)?/gi,
  )) {
    if (CONTEXT.financial.test(ctxAt(m.index))) {
      push(m.index, m.index + m[0].length, "FINANCIAL", 0.7);
    }
  }

  for (const m of text.matchAll(
    /\b\d{1,5}[A-Za-z]?(?:\/\d+)?,?\s+(?:[A-Z][\w.'-]*\s+){0,4}(?:Lane|Road|Rd|Street|St|Marg|Nagar|Colony|Avenue|Ave|Sector|Block|Layout|Cross|Main|Path|Gali|Chowk|Enclave|Apartments?|Society|Bagh|Vihar|Puram|Drive|Boulevard)\b\.?(?:,\s*[A-Z][A-Za-z .'-]*){0,4}(?:,?\s*(?:\d{3}\s?\d{3}|\d{5}(?:-\d{4})?)\b)?/g,
  )) {
    const value = m[0].trimEnd();
    push(m.index, m.index + value.length, "ADDRESS", 0.75);
  }

  for (const m of text.matchAll(
    /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt|Sri|Kumari)\.?\s+((?:\p{Lu}[\p{Ll}'’-]+|\p{Lu}\.)(?:\s+(?:\p{Lu}[\p{Ll}'’-]+|\p{Lu}\.)){0,3})/dgu,
  )) {
    const span = m.indices?.[1];
    if (span) push(span[0], span[1], "PERSON", 0.85);
  }

  for (const m of text.matchAll(/\b\p{Lu}\p{Ll}{1,20}\b/gu)) {
    if (!FIRST_NAMES.has(m[0].toLowerCase())) continue;
    let end = m.index + m[0].length;
    const surname = /\s+(\p{Lu}\p{Ll}{1,20})\b/uy;
    let surnames = 0;
    while (surnames < 2) {
      surname.lastIndex = end;
      const next = surname.exec(text);
      if (!next || NOT_A_SURNAME.has(next[1]!.toLowerCase())) break;
      end = surname.lastIndex;
      surnames += 1;
    }
    if (surnames > 0) push(m.index, end, "PERSON", 0.7);
  }

  for (const field of fields) {
    const label = field.label;
    if (NAME_LABEL.test(label) && !NON_PERSON_NAME_LABEL.test(label)) {
      const value = cleanFieldValue(text, field, /[,;(|]|\s[-–]\s/);
      if (value && isPlausibleName(value.value)) push(value.start, value.end, "PERSON", 0.9);
      continue;
    }
    if (ADDRESS_LABEL.test(label) && !NON_POSTAL_ADDRESS_LABEL.test(label)) {
      const value = cleanFieldValue(text, field);
      if (value && value.value.length >= 8 && /\p{L}/u.test(value.value)) {
        push(value.start, value.end, "ADDRESS", 0.85);
      }
      continue;
    }
    if (CONTEXT.dob.test(label)) {
      const value = cleanFieldValue(text, field);
      if (value && /\d/.test(value.value) && value.value.length <= 40) {
        push(value.start, value.end, "DATE_OF_BIRTH", 0.9);
      }
      continue;
    }
    if (CONTEXT.aadhaar.test(label)) {
      const value = cleanFieldValue(text, field);
      if (value && /^\d{4}[ -]?\d{4}[ -]?\d{4}$/.test(value.value)) {
        push(value.start, value.end, "AADHAAR", 0.92);
      }
      continue;
    }
    if (CONTEXT.phone.test(label) && !/e-?mail/i.test(label)) {
      const value = cleanFieldValue(text, field);
      const match = value && /\+?\d[\d\s().-]{5,18}\d/.exec(value.value);
      if (value && match) {
        const count = digitsOf(match[0]).length;
        const start = value.start + match.index;
        if (count >= 7 && count <= 15) push(start, start + match[0].length, "PHONE", 0.85);
      }
      continue;
    }
    if (CONTEXT.bank.test(label) && !/\b(?:e-?mail|holder|name|type|ifsc|branch)\b/i.test(label)) {
      const value = cleanFieldValue(text, field);
      const match = value && /\d[\d\s-]{7,22}\d/.exec(value.value);
      if (value && match) {
        const count = digitsOf(match[0]).length;
        const start = value.start + match.index;
        if (count >= 9 && count <= 18) push(start, start + match[0].length, "BANK_ACCOUNT", 0.85);
      }
      continue;
    }
    if (CONTEXT.financial.test(label)) {
      const value = cleanFieldValue(text, field);
      if (value && /\d/.test(value.value) && value.value.length <= 60) {
        push(value.start, value.end, "FINANCIAL", 0.75);
      }
      continue;
    }
    const isStudent = STUDENT_LABEL.test(label);
    const isGovernment = GOVERNMENT_LABEL.test(label);
    const isReference = REFERENCE_LABEL.test(label);
    if ((isStudent || isGovernment || isReference) && (ID_WORD.test(label) || isGovernment)) {
      const value = cleanFieldValue(text, field);
      const token = value && /^[A-Za-z0-9][A-Za-z0-9/_.-]{2,39}/.exec(value.value);
      if (value && token && /\d/.test(token[0])) {
        const category: CategoryKey = isGovernment
          ? "GOVERNMENT_ID"
          : isStudent
            ? "STUDENT_ID"
            : "REFERENCE_ID";
        push(value.start, value.start + token[0].length, category, 0.8);
      }
    }
  }

  // A confidently detected name or address is redacted everywhere it repeats.
  const propagated = new Set<string>();
  for (const detection of [...detections]) {
    if (detection.category !== "PERSON" && detection.category !== "ADDRESS") continue;
    if (detection.confidence < 0.8) continue;
    const value = text.slice(detection.start, detection.end);
    const key = `${detection.category}:${value}`;
    if (value.length < 5 || propagated.has(key)) continue;
    propagated.add(key);
    let index = text.indexOf(value);
    while (index !== -1) {
      if (index !== detection.start && wordBoundaryAt(text, index, index + value.length)) {
        push(index, index + value.length, detection.category, detection.confidence - 0.05);
      }
      index = text.indexOf(value, index + value.length);
    }
  }

  return detections;
}

export const rulesProvider: DetectionProvider = {
  id: "rules",
  label: "Built-in rules",
  isConfigured: () => true,
  async detect(text: string, ctx: DetectContext) {
    return detectWithRules(text, ctx.fields);
  },
};
