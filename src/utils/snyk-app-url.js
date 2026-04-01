/**
 * Parse Snyk web app project/issue links, e.g.
 * https://app.snyk.io/org/my-org/project/{projectUuid}#issue-{issueUuid}
 *
 * The fragment UUID is the JSON:API resource id for the issue (GET .../issues/{id}).
 * @param {string} raw
 * @returns {{ issueUuid: string | null; projectId: string | null; orgSlug: string | null } | null}
 */
export function parseSnykAppIssueUrl(raw) {
  const s = raw.trim();
  if (!s) return null;

  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }

  const host = u.hostname.toLowerCase();
  if (!host.endsWith('snyk.io')) {
    return null;
  }

  const issueHash = u.hash.match(
    /^#issue-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i
  );
  let issueUuid = issueHash ? issueHash[1] : null;
  if (!issueUuid) {
    const bareHash = u.hash.match(
      /^#([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i
    );
    if (bareHash) issueUuid = bareHash[1];
  }

  const projectMatch = u.pathname.match(
    /\/project\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i
  );
  const orgMatch = u.pathname.match(/\/org\/([^/?#]+)/i);

  return {
    issueUuid,
    projectId: projectMatch ? projectMatch[1] : null,
    orgSlug: orgMatch ? decodeURIComponent(orgMatch[1]) : null,
  };
}
