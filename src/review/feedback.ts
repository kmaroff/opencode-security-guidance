const MARKER = "[security-guidance synthetic feedback]"

export function feedbackMarker(): string {
  return MARKER
}

export function formatFeedback(findings: Array<Record<string, unknown>>): string {
  const lines = [
    MARKER,
    "Security review found validated potential vulnerabilities. Address each or explain why it is not exploitable:",
  ]
  for (const finding of findings) {
    lines.push(`- [${String(finding.severity).toUpperCase()}] ${String(finding.category)} in ${String(finding.filePath)}`)
    lines.push(`  Code: ${String(finding.vulnerableCode)}`)
    lines.push(`  Why: ${String(finding.explanation)}`)
    lines.push(`  Fix: ${String(finding.fix)}`)
  }
  lines.push("Continue the user's original request after addressing this supplementary feedback.")
  return lines.join("\n")
}

export function hasFeedbackMarker(parts: unknown): boolean {
  if (!Array.isArray(parts)) return false
  return parts.some(part => part && typeof part === "object" && typeof (part as Record<string, unknown>).text === "string" && ((part as Record<string, unknown>).text as string).includes(MARKER))
}
