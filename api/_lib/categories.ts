// PII categories shared by every provider. Labels match the frontend's
// category strings (see src/lib/mock-scan-data.ts) so the UI renders live
// findings exactly like the demo fixtures.

export type RiskLevel = "high" | "medium" | "low";

export interface CategoryInfo {
  label: string;
  risk: RiskLevel;
  replaceLabel: string;
  explanation: string;
  recommendedAction: string;
}

export const CATEGORIES = {
  PERSON: {
    label: "Person name",
    risk: "medium",
    replaceLabel: "NAME",
    explanation: "A name is context-dependent and may not need redaction in every document.",
    recommendedAction: "Confirm that the recipient needs this name.",
  },
  EMAIL: {
    label: "Email address",
    risk: "high",
    replaceLabel: "EMAIL",
    explanation: "This resembles an email address. Confirm that the recipient needs it.",
    recommendedAction: "Confirm that the recipient needs this email address.",
  },
  PHONE: {
    label: "Phone number",
    risk: "high",
    replaceLabel: "PHONE",
    explanation:
      "This looks like a personal phone number; sharing it exposes a direct contact channel.",
    recommendedAction: "Remove unless the recipient must call the person directly.",
  },
  ADDRESS: {
    label: "Residential address",
    risk: "high",
    replaceLabel: "ADDRESS",
    explanation: "A residential address can identify where a person lives.",
    recommendedAction: "Remove unless the recipient needs the postal address.",
  },
  AADHAAR: {
    label: "Aadhaar-style number",
    risk: "high",
    replaceLabel: "AADHAAR-STYLE NUMBER",
    explanation:
      "This number matches a sensitive-identifier pattern; verify the context before sharing.",
    recommendedAction: "Verify the context before sharing.",
  },
  PAN: {
    label: "PAN-style identifier",
    risk: "high",
    replaceLabel: "PAN-STYLE IDENTIFIER",
    explanation:
      "This value matches a sensitive-identifier pattern; verify the context before sharing.",
    recommendedAction: "Verify the context before sharing.",
  },
  CREDIT_CARD: {
    label: "Payment card number",
    risk: "high",
    replaceLabel: "CARD NUMBER",
    explanation: "This number passes the Luhn checksum used by payment cards.",
    recommendedAction: "Remove payment card numbers before sharing.",
  },
  BANK_ACCOUNT: {
    label: "Bank-account-like number",
    risk: "high",
    replaceLabel: "BANK-ACCOUNT-LIKE NUMBER",
    explanation: "This value has the shape of a bank-account-like number; sharing it can enable fraud.",
    recommendedAction: "Verify the context before sharing.",
  },
  GOVERNMENT_ID: {
    label: "Government identifier",
    risk: "high",
    replaceLabel: "GOVERNMENT ID",
    explanation: "This value matches a government-issued identifier pattern.",
    recommendedAction: "Verify the context before sharing.",
  },
  DATE_OF_BIRTH: {
    label: "Date of birth",
    risk: "medium",
    replaceLabel: "DATE OF BIRTH",
    explanation: "A date of birth is a common identity-verification factor.",
    recommendedAction: "Remove unless the date of birth is required for the application.",
  },
  STUDENT_ID: {
    label: "Student identifier",
    risk: "medium",
    replaceLabel: "STUDENT ID",
    explanation:
      "An application or roll number can link the document back to an individual applicant.",
    recommendedAction: "Confirm whether the recipient needs this reference number.",
  },
  REFERENCE_ID: {
    label: "Reference identifier",
    risk: "medium",
    replaceLabel: "REFERENCE ID",
    explanation: "A customer, employee or member reference can link the document to a person.",
    recommendedAction: "Confirm whether the recipient needs this reference number.",
  },
  FINANCIAL: {
    label: "Financial detail",
    risk: "medium",
    replaceLabel: "FINANCIAL DETAIL",
    explanation: "Income or other financial details are sensitive in many contexts.",
    recommendedAction: "Remove unless the financial detail is required.",
  },
  IP_ADDRESS: {
    label: "IP address",
    risk: "low",
    replaceLabel: "IP ADDRESS",
    explanation: "An IP address can sometimes be linked to a household or device.",
    recommendedAction: "Remove unless the recipient needs network details.",
  },
  LOCATION: {
    label: "Location",
    risk: "low",
    replaceLabel: "LOCATION",
    explanation: "A place name may narrow down where a person lives or works.",
    recommendedAction: "Review whether the location is necessary.",
  },
  OTHER: {
    label: "Other personal data",
    risk: "low",
    replaceLabel: "REDACTED",
    explanation: "A detection provider flagged this value as potentially personal data.",
    recommendedAction: "Review the context before sharing.",
  },
} as const satisfies Record<string, CategoryInfo>;

export type CategoryKey = keyof typeof CATEGORIES;

const LABEL_TO_KEY = new Map<string, CategoryKey>(
  (Object.keys(CATEGORIES) as CategoryKey[]).map((key) => [CATEGORIES[key].label, key]),
);

export function categoryKeyFromLabel(label: string): CategoryKey | undefined {
  return LABEL_TO_KEY.get(label);
}

/**
 * Provider entity name -> PII category. Unknown entities map to OTHER so a
 * provider can never silently drop a detection because of naming.
 */
const ENTITY_MAP: Record<string, CategoryKey> = {
  // Presidio
  PERSON: "PERSON",
  EMAIL_ADDRESS: "EMAIL",
  PHONE_NUMBER: "PHONE",
  CREDIT_CARD: "CREDIT_CARD",
  IP_ADDRESS: "IP_ADDRESS",
  IN_AADHAAR: "AADHAAR",
  IN_PAN: "PAN",
  IN_PASSPORT: "GOVERNMENT_ID",
  IN_VOTER: "GOVERNMENT_ID",
  IN_VEHICLE_REGISTRATION: "GOVERNMENT_ID",
  US_SSN: "GOVERNMENT_ID",
  US_PASSPORT: "GOVERNMENT_ID",
  US_DRIVER_LICENSE: "GOVERNMENT_ID",
  UK_NHS: "GOVERNMENT_ID",
  US_BANK_NUMBER: "BANK_ACCOUNT",
  IBAN_CODE: "BANK_ACCOUNT",
  LOCATION: "LOCATION",
  // Google Cloud Sensitive Data Protection (DLP)
  PERSON_NAME: "PERSON",
  FIRST_NAME: "PERSON",
  LAST_NAME: "PERSON",
  CREDIT_CARD_NUMBER: "CREDIT_CARD",
  DATE_OF_BIRTH: "DATE_OF_BIRTH",
  STREET_ADDRESS: "ADDRESS",
  INDIA_AADHAAR_INDIVIDUAL: "AADHAAR",
  INDIA_PAN_INDIVIDUAL: "PAN",
  INDIA_PASSPORT: "GOVERNMENT_ID",
  INDIA_GST_INDIVIDUAL: "GOVERNMENT_ID",
  US_SOCIAL_SECURITY_NUMBER: "GOVERNMENT_ID",
  PASSPORT: "GOVERNMENT_ID",
  FINANCIAL_ACCOUNT_NUMBER: "BANK_ACCOUNT",
  US_BANK_ROUTING_MICR: "BANK_ACCOUNT",
  // Sapling and other common spellings
  NAME: "PERSON",
  EMAIL: "EMAIL",
  PHONE: "PHONE",
  ADDRESS: "ADDRESS",
  DOB: "DATE_OF_BIRTH",
  SSN: "GOVERNMENT_ID",
  CREDIT_CARD_NO: "CREDIT_CARD",
  BANK_ACCOUNT: "BANK_ACCOUNT",
  IP: "IP_ADDRESS",
};

export function normalizeEntity(entity: string): CategoryKey {
  const key = entity.trim().toUpperCase().replace(/[\s-]+/g, "_");
  return ENTITY_MAP[key] ?? "OTHER";
}
