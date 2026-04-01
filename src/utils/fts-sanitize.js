/**
 * FTS5 query sanitizer — prevents syntax errors from user input.
 *
 * Two-path strategy:
 *   Boolean mode (AND/OR/NOT detected): narrow strip, preserve quotes
 *   Standard mode: aggressive strip of all FTS5 special chars
 */

const BOOLEAN_OPERATORS = new Set(["AND", "OR", "NOT"]);

function sanitizeFtsInput(input) {
  const tokens = input.split(/\s+/).filter(t => t.length > 0);
  if (tokens.length === 0) return "";

  if (tokens.some(t => BOOLEAN_OPERATORS.has(t))) {
    return input.replace(/[{}[\]^~*:/]/g, " ").replace(/\s+/g, " ").trim();
  }

  const cleaned = input
    .replace(/['\"(){}[\]^~*:@#$%&+=<>|\\/.!?,;]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  return cleaned.split(/\s+/).filter(t => t.length > 0 && !BOOLEAN_OPERATORS.has(t)).join(" ");
}

function buildFtsMatchExpr(input) {
  const sanitized = sanitizeFtsInput(input);
  const tokens = sanitized.split(/\s+/).filter(t => t.length > 0);
  if (tokens.length === 0) return input.replace(/[^a-zA-Z0-9\s]/g, "").trim() || "empty";
  return tokens.length > 1 ? tokens.join(" OR ") : sanitized;
}

export { sanitizeFtsInput, buildFtsMatchExpr };

