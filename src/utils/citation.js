/**
 * Citation metadata for the deterministic citation pipeline.
 *
 * Provides structured identifiers (canonical_ref, display_text, aliases)
 * that the platform's entity linker uses to match references in agent
 * responses to MCP tool results — without relying on LLM formatting.
 *
 * See: docs/guides/law-mcp-golden-standard.md Section 4.9c
 */

/**
 * Build citation metadata for any retrieval tool response.
 *
 * @param {string} canonicalRef  Primary reference the entity linker matches against
 * @param {string} displayText   How the reference appears in prose
 * @param {string} toolName      The MCP tool name
 * @param {Record<string, string>} toolArgs The tool arguments for verification lookup
 * @param {string|null} [sourceUrl] Official portal URL (optional)
 * @param {string[]} [aliases]   Alternative names the LLM might use (optional)
 * @returns {{ canonical_ref: string, display_text: string, aliases?: string[], source_url?: string, lookup: { tool: string, args: Record<string, string> } }}
 */
export function buildCitation(canonicalRef, displayText, toolName, toolArgs, sourceUrl, aliases) {
  return {
    canonical_ref: canonicalRef,
    display_text: displayText,
    ...(aliases && aliases.length > 0 && { aliases }),
    ...(sourceUrl && { source_url: sourceUrl }),
    lookup: {
      tool: toolName,
      args: toolArgs,
    },
  };
}
