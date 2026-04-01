/**
 * Extract org slug from a Snyk web UI URL or return a bare slug.
 * Examples:
 * - "https://app.snyk.io/org/my-org/issues/..." -> "my-org"
 * - "my-org" -> "my-org"
 *
 * @param {string} input
 * @returns {string}
 */
export function parseOrgSlugFromInput(input) {
  const trimmed = String(input).trim();
  if (!trimmed) {
    throw new Error('org_slug_or_url must be non-empty');
  }

  const pathMatch = trimmed.match(/snyk\.io\/org\/([^/?#]+)/i);
  if (pathMatch) {
    return decodeURIComponent(pathMatch[1]);
  }

  try {
    const u = new URL(trimmed);
    const m = u.pathname.match(/\/org\/([^/?#]+)/);
    if (m) {
      return decodeURIComponent(m[1]);
    }
  } catch {
    /* bare slug */
  }

  return trimmed.replace(/^\/+|\/+$/g, '');
}
