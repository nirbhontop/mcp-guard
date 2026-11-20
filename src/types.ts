export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  ruleId: string;
  severity: Severity;
  file: string;
  line?: number;
  title: string;
  detail: string;
  remediation: string;
}

export interface AuditReport {
  scannedPath: string;
  filesChecked: number;
  findings: Finding[];
  score: number;
}
