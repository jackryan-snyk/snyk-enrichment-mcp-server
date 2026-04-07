/**
 * @import { SnykClient } from '../utils/snyk-client.js'
 */
import { parseOrgSlugFromInput } from '../utils/org-slug.js';
import { parseSnykAppIssueUrl } from '../utils/snyk-app-url.js';

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * @param {unknown} projectResource JSON:API project resource (`data` from GET project)
 * @returns {string | null}
 */
function targetIdFromProjectResource(projectResource) {
  const rel = projectResource?.relationships?.target?.data;
  if (!rel) return null;
  if (Array.isArray(rel)) {
    const first = rel.find((x) => typeof x?.id === 'string');
    return first?.id ?? null;
  }
  return typeof rel?.id === 'string' ? rel.id : null;
}

/**
 * Snyk project `attributes.origin` for SCM-backed projects is typically `github`.
 * @param {unknown} origin
 */
function isGithubProjectOrigin(origin) {
  if (origin == null) return false;
  const s = String(origin).trim().toLowerCase();
  return s === 'github';
}

/**
 * Normalize an identifier copied from Jira/HTML (trim, decode URI once).
 * @param {string} raw
 */
function normalizeExternalIssueId(raw) {
  let s = raw.trim();
  try {
    s = decodeURIComponent(s);
  } catch {
    /* keep as-is */
  }
  return s.trim();
}

/**
 * Jira / integrations sometimes prefix the REST UUID with `issue-`.
 * @param {string} normalized
 */
function stripIssuePrefixIfUuid(normalized) {
  const t = normalized.trim();
  const m = t.match(
    /^issue-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i
  );
  return m ? m[1] : t;
}

/**
 * @param {string} raw
 */
function normalizeCwe(raw) {
  const s = raw.trim().toUpperCase();
  if (!s) return s;
  if (s.startsWith('CWE-')) return s;
  if (/^\d+$/.test(s)) return `CWE-${s}`;
  return s;
}

/**
 * @param {unknown} v
 * @returns {string[]}
 */
function deepCollectStrings(v) {
  /** @type {string[]} */
  const out = [];
  if (v == null) return out;
  if (typeof v === 'string') {
    out.push(v);
    return out;
  }
  if (Array.isArray(v)) {
    for (const x of v) out.push(...deepCollectStrings(x));
    return out;
  }
  if (typeof v === 'object') {
    for (const x of Object.values(v)) out.push(...deepCollectStrings(x));
  }
  return out;
}

/**
 * @param {unknown} attr attributes object
 * @param {string} needle
 */
function coordinateBlobContains(attr, needle) {
  const coords = attr?.coordinates;
  if (!needle?.trim() || !Array.isArray(coords)) return false;
  const n = needle.toLowerCase();
  return coords.some((c) =>
    deepCollectStrings(c).some((s) => s.toLowerCase().includes(n))
  );
}

/**
 * @param {unknown} attr
 * @param {string} wantCwe normalized CWE-###
 */
function attributeHasCwe(attr, wantCwe) {
  const classes = attr?.classes;
  if (Array.isArray(classes)) {
    const hit = classes.some(
      (c) =>
        typeof c?.id === 'string' && c.id.toUpperCase() === wantCwe.toUpperCase()
    );
    if (hit) return true;
  }
  const problems = attr?.problems;
  if (Array.isArray(problems)) {
    return problems.some((p) => {
      const id = p?.id;
      if (typeof id !== 'string') return false;
      return id.toUpperCase() === wantCwe.toUpperCase();
    });
  }
  return false;
}

/**
 * @param {unknown} attr
 * @param {string} isoDate YYYY-MM-DD — compare to issue created_at (UTC day) or date prefix
 */
function createdAtMatchesDate(attr, isoDate) {
  const created = attr?.created_at;
  if (typeof created !== 'string' || !isoDate) return false;
  const day = isoDate.slice(0, 10);
  return created.slice(0, 10) === day;
}

/**
 * @param {Record<string, unknown>} filters
 */
function issueRowMatchesHeuristics(row, filters) {
  const attr = row?.attributes;
  if (!attr || typeof attr !== 'object') return false;

  if (filters.cwe) {
    const want = normalizeCwe(String(filters.cwe));
    if (!attributeHasCwe(attr, want)) return false;
  }

  if (filters.risk_score !== undefined && filters.risk_score !== null) {
    const val = attr.risk?.score?.value;
    if (val !== filters.risk_score) return false;
  }

  if (filters.title_contains) {
    const t = String(attr.title ?? '');
    if (!t.toLowerCase().includes(String(filters.title_contains).toLowerCase())) {
      return false;
    }
  }

  if (filters.created_date) {
    if (!createdAtMatchesDate(attr, String(filters.created_date))) return false;
  }

  if (filters.file_path_contains) {
    if (!coordinateBlobContains(attr, String(filters.file_path_contains))) {
      return false;
    }
  }

  return true;
}

/**
 * @param {SnykClient} client
 * @param {string} orgId
 * @param {string} projectId
 * @param {{ type?: string }} [opts]
 */
async function* iterateProjectIssues(client, orgId, projectId, opts = {}) {
  /** @type {Record<string, string | number>} */
  const baseParams = {
    'scan_item.type': 'project',
    'scan_item.id': projectId,
    limit: 100,
  };
  if (opts.type) {
    baseParams.type = opts.type;
  }

  let payload = await client.get(`/orgs/${orgId}/issues`, baseParams);
  for (;;) {
    const rows = payload?.data;
    if (!Array.isArray(rows)) {
      throw new Error('Unexpected issues list response shape');
    }
    for (const row of rows) {
      yield row;
    }
    const next = payload?.links?.next ?? null;
    if (!next) break;
    payload = await client.getAbsolute(next);
  }
}

/**
 * True if this row is the issue we're looking for.
 * - SCA/Open Source: often `problems[].id` (e.g. SNYK-JS-…) or `attributes.key` (e.g. npm:pkg:…).
 * - Snyk Code/SAST: usually `attributes.key` (opaque fingerprint) and sometimes `key_asset`.
 * @param {unknown} issueLike
 * @param {string} identifier normalized external id
 */
function issueMatchesExternalIdentifier(issueLike, identifier) {
  const want = identifier;
  if (!want) return false;

  // Snyk UI #issue-{uuid} matches resource id in list responses; sometimes echoed as attributes.key.
  if (UUID_RE.test(want) && issueLike?.id === want) return true;

  const attr = issueLike?.attributes;
  if (!attr || typeof attr !== 'object') return false;

  const problems = attr.problems;
  if (Array.isArray(problems)) {
    const hitProblem = problems.some(
      (p) =>
        p?.id === want ||
        (typeof p?.id === 'string' && p.id.toLowerCase() === want.toLowerCase())
    );
    if (hitProblem) return true;
  }

  if (attr.key === want) return true;
  if (
    typeof attr.key === 'string' &&
    attr.key.toLowerCase() === want.toLowerCase()
  ) {
    return true;
  }

  if (attr.key_asset === want) return true;
  if (
    typeof attr.key_asset === 'string' &&
    attr.key_asset.toLowerCase() === want.toLowerCase()
  ) {
    return true;
  }

  return false;
}

/**
 * @param {SnykClient} client
 * @param {string} orgId
 * @param {string} projectId
 * @param {string} externalId
 * @param {{ type?: string }} [opts]
 */
async function findIssueUuidByExternalId(client, orgId, projectId, externalId, opts = {}) {
  for await (const row of iterateProjectIssues(client, orgId, projectId, opts)) {
    if (issueMatchesExternalIdentifier(row, externalId)) {
      return row.id;
    }
  }
  return null;
}

/**
 * @param {SnykClient} client
 * @param {string} orgId
 * @param {string} projectId
 * @param {Record<string, unknown>} filters
 * @param {{ type?: string }} [opts]
 * @returns {Promise<{ candidates: { id: string; title: string | null; cwe: string[]; risk_score: number | null; created_at: string | null }[] }>}
 */
async function findIssueCandidatesByHeuristics(client, orgId, projectId, filters, opts = {}) {
  /** @type {{ id: string; title: string | null; cwe: string[]; risk_score: number | null; created_at: string | null }[]} */
  const candidates = [];

  for await (const row of iterateProjectIssues(client, orgId, projectId, opts)) {
    if (!issueRowMatchesHeuristics(row, filters)) continue;
    const attr = row.attributes;
    const cwes = [];
    if (Array.isArray(attr?.classes)) {
      for (const c of attr.classes) {
        if (typeof c?.id === 'string') cwes.push(c.id);
      }
    }
    if (Array.isArray(attr?.problems)) {
      for (const p of attr.problems) {
        if (typeof p?.id === 'string' && /^CWE-/i.test(p.id)) cwes.push(p.id);
      }
    }
    candidates.push({
      id: row.id,
      title: typeof attr?.title === 'string' ? attr.title : null,
      created_at: typeof attr?.created_at === 'string' ? attr.created_at : null,
      risk_score:
        typeof attr?.risk?.score?.value === 'number'
          ? attr.risk.score.value
          : null,
      cwe: [...new Set(cwes)],
    });
  }

  return { candidates };
}

/**
 * @param {SnykClient} client
 */
export function createEnrichmentTools(client) {
  return [
    {
      name: 'snyk_resolve_org_id_from_slug',
      description:
        'Resolve a Snyk organization UUID from its URL slug (e.g. https://app.snyk.io/org/my-org/... or my-org). Uses GET /orgs with the slug filter. Requires SNYK_API_TOKEN.',
      inputSchema: {
        type: 'object',
        properties: {
          org_slug_or_url: {
            type: 'string',
            description:
              'Org slug (my-org) or full Snyk app URL containing /org/{slug}/',
          },
        },
        required: ['org_slug_or_url'],
      },
      /** @param {{ org_slug_or_url?: string }} args */
      handler: async (args) => {
        const slug = parseOrgSlugFromInput(args.org_slug_or_url ?? '');
        const res = await client.get('/orgs', { slug });
        const first = res?.data?.[0];
        if (!first?.id) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    error: 'No organization found for slug',
                    slug,
                    hint: 'Check the slug and that your token can access this org.',
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          };
        }
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  org_id: first.id,
                  slug: first.attributes?.slug ?? slug,
                  name: first.attributes?.name ?? null,
                },
                null,
                2
              ),
            },
          ],
        };
      },
    },
    {
      name: 'snyk_get_org_issue_details',
      description:
        'Fetch full issue details via GET /orgs/{org_id}/issues/{issue_id} (see https://docs.snyk.io/snyk-api/reference/issues ). (1) If issue_id is a REST UUID (optional Jira prefix `issue-`), loads directly. (2) If issue_id is a full app link like https://app.snyk.io/org/{slug}/project/{projectId}#issue-{uuid}, org_id is optional (slug taken from URL), project_id optional, and the fragment UUID is the REST issue id (same as `data.id` / UI deep link). (3) Else if issue_id is a Snyk key / SNYK-* id, requires project_id and scans that project. (4) For Snyk Code when the ticket has no usable id, omit issue_id and pass project_id plus match_* fields: Snyk matches ALL provided heuristics (CWE, risk score, title substring, created date YYYY-MM-DD, file path substring in coordinates). Default heuristic scan uses issue_type `code`. If more than one issue matches, returns candidate summaries instead of failing silently.',
      inputSchema: {
        type: 'object',
        properties: {
          org_id: {
            type: 'string',
            description:
              'Snyk organization UUID. Optional if issue_id is a full app.snyk.io URL that includes /org/{slug}/ (slug is resolved via GET /orgs?slug=).',
          },
          project_id: {
            type: 'string',
            description:
              'Snyk project UUID. Optional when issue_id is a full app URL with /project/{id}/. Required when issue_id is not a REST UUID (unless URL provides it), and for heuristic SAST matching.',
          },
          issue_id: {
            type: 'string',
            description:
              'Full app.snyk.io project issue URL with #issue-{uuid}, or REST issue UUID (with or without `issue-` prefix), or Snyk Code key, SNYK-* problem id, or key_asset. Omit when using match_* heuristics only.',
          },
          issue_type: {
            type: 'string',
            description:
              'Optional filter for list-org-issues: `code` (default for heuristic mode), `package_vulnerability`, `license`, `cloud`, `config`, `custom`. When resolving by external id, lookup retries once without this filter if the first pass fails.',
            enum: [
              'code',
              'package_vulnerability',
              'license',
              'cloud',
              'config',
              'custom',
            ],
          },
          match_cwe: {
            type: 'string',
            description:
              'Snyk Code: CWE id (e.g. CWE-89 or 89). Matched against attributes.classes and problems.',
          },
          match_risk_score: {
            type: 'integer',
            description:
              'Snyk priority score: attributes.risk.score.value (0–1000 per API).',
          },
          match_title_contains: {
            type: 'string',
            description: 'Case-insensitive substring match on attributes.title.',
          },
          match_created_date: {
            type: 'string',
            description:
              'UTC date the issue was created (YYYY-MM-DD), compared to attributes.created_at.',
          },
          match_file_path_contains: {
            type: 'string',
            description:
              'Substring matched against file paths / locations inside attributes.coordinates (Snyk Code).',
          },
        },
        required: [],
      },
      /** @param {Record<string, unknown>} args */
      handler: async (args) => {
        let orgId = String(args.org_id ?? '').trim();
        const rawInput = args.issue_id != null ? String(args.issue_id) : '';

        const fromAppUrl = parseSnykAppIssueUrl(rawInput);
        let projectId = String(args.project_id ?? '').trim();
        if (!projectId && fromAppUrl?.projectId) {
          projectId = fromAppUrl.projectId;
        }

        let issueToken = rawInput.trim();
        if (fromAppUrl?.issueUuid) {
          issueToken = fromAppUrl.issueUuid;
        } else if (fromAppUrl && !fromAppUrl.issueUuid) {
          issueToken = '';
        }

        const externalIdRaw = normalizeExternalIssueId(issueToken);
        const externalId = stripIssuePrefixIfUuid(externalIdRaw);

        if (!orgId && fromAppUrl?.orgSlug) {
          const slugRes = await client.get('/orgs', {
            slug: fromAppUrl.orgSlug,
          });
          const orgFirst = slugRes?.data?.[0];
          if (!orgFirst?.id) {
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      error: 'Could not resolve org from URL slug',
                      slug: fromAppUrl.orgSlug,
                    },
                    null,
                    2
                  ),
                },
              ],
              isError: true,
            };
          }
          orgId = orgFirst.id;
        }

        const issueTypeArg = String(args.issue_type ?? '').trim();
        const issueType = issueTypeArg || undefined;

        const heuristicFilters = {
          cwe: args.match_cwe,
          risk_score: args.match_risk_score,
          title_contains: args.match_title_contains,
          created_date: args.match_created_date,
          file_path_contains: args.match_file_path_contains,
        };

        const heuristicActive = Object.keys(heuristicFilters).some((k) => {
          const v = heuristicFilters[k];
          if (k === 'risk_score') return v !== undefined && v !== null;
          return v !== undefined && v !== null && String(v).trim() !== '';
        });

        const hasIssueId = externalId.length > 0;

        if (!orgId) {
          return {
            content: [
              {
                type: 'text',
                text:
                  'org_id is required unless issue_id is a full app.snyk.io URL that includes an /org/{slug}/ path (slug is resolved automatically).',
              },
            ],
            isError: true,
          };
        }

        if (!hasIssueId && !heuristicActive) {
          return {
            content: [
              {
                type: 'text',
                text:
                  'Provide issue_id (app.snyk.io URL with #issue-{uuid}, REST UUID, Snyk key, or SNYK-* id), or provide at least one match_* field with project_id for heuristic SAST lookup.',
              },
            ],
            isError: true,
          };
        }

        const resolvedRestUuid = hasIssueId && UUID_RE.test(externalId);
        if (!resolvedRestUuid && !projectId && (hasIssueId || heuristicActive)) {
          return {
            content: [
              {
                type: 'text',
                text:
                  'project_id is required unless issue_id is already a REST UUID (after stripping an optional `issue-` prefix).',
              },
            ],
            isError: true,
          };
        }

        // Heuristic-only branch (Snyk Code / Jira fields)
        if (heuristicActive && !hasIssueId) {
          const listType = issueType ?? 'code';
          let { candidates } = await findIssueCandidatesByHeuristics(
            client,
            orgId,
            projectId,
            heuristicFilters,
            { type: listType }
          );

          if (candidates.length === 0) {
            ({ candidates } = await findIssueCandidatesByHeuristics(
              client,
              orgId,
              projectId,
              heuristicFilters,
              {}
            ));
          }

          if (candidates.length === 0) {
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      error: 'No issues matched the given match_* filters in this project',
                      org_id: orgId,
                      project_id: projectId,
                      filters: heuristicFilters,
                    },
                    null,
                    2
                  ),
                },
              ],
              isError: true,
            };
          }

          if (candidates.length > 1) {
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      error:
                        'Multiple issues matched; narrow match_* fields or use REST issue UUID',
                      org_id: orgId,
                      project_id: projectId,
                      filters: heuristicFilters,
                      candidates,
                    },
                    null,
                    2
                  ),
                },
              ],
              isError: true,
            };
          }

          const restIssueId = candidates[0].id;
          const issue = await client.get(
            `/orgs/${orgId}/issues/${restIssueId}`
          );
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    resolution: 'heuristic_single_match',
                    filters: heuristicFilters,
                    resolved_rest_issue_id: restIssueId,
                    issue,
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        let restIssueId = externalId;

        if (!UUID_RE.test(externalId)) {
          const typeOpts = issueType ? { type: issueType } : {};
          let found = await findIssueUuidByExternalId(
            client,
            orgId,
            projectId,
            externalId,
            typeOpts
          );
          let retriedWithoutType = false;
          if (!found && issueType) {
            found = await findIssueUuidByExternalId(
              client,
              orgId,
              projectId,
              externalId,
              {}
            );
            retriedWithoutType = true;
          }

          if (!found && heuristicActive) {
            for await (const row of iterateProjectIssues(
              client,
              orgId,
              projectId,
              issueType ? { type: issueType } : {}
            )) {
              if (
                issueMatchesExternalIdentifier(row, externalId) &&
                issueRowMatchesHeuristics(row, heuristicFilters)
              ) {
                found = row.id;
                break;
              }
            }
          }

          if (!found && heuristicActive && issueType) {
            for await (const row of iterateProjectIssues(client, orgId, projectId, {})) {
              if (
                issueMatchesExternalIdentifier(row, externalId) &&
                issueRowMatchesHeuristics(row, heuristicFilters)
              ) {
                found = row.id;
                break;
              }
            }
          }

          if (!found) {
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      error:
                        'No issue found for this identifier in this project (checked problems[].id, attributes.key, key_asset)',
                      org_id: orgId,
                      project_id: projectId,
                      issue_id: externalId,
                      issue_type_filter: issueType ?? null,
                      retried_without_type: retriedWithoutType,
                      filters_used: heuristicActive ? heuristicFilters : undefined,
                    },
                    null,
                    2
                  ),
                },
              ],
              isError: true,
            };
          }
          restIssueId = found;
        }

        const issue = await client.get(`/orgs/${orgId}/issues/${restIssueId}`);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  requested_issue_id: hasIssueId ? externalId : null,
                  resolved_rest_issue_id: restIssueId,
                  issue,
                },
                null,
                2
              ),
            },
          ],
        };
      },
    },
    {
      name: 'snyk_get_project_github_repo_url',
      description:
        'Resolve the Git repository URL for a Snyk project when it is GitHub-backed. Calls GET /orgs/{org_id}/projects/{project_id}; if attributes.origin is `github`, follows relationships.target to GET /orgs/{org_id}/targets/{target_id} and returns attributes.url as `url`. Uses the same REST API version as other tools (today's date YYYY-MM-DD for the version query param and Snyk-Version header). Requires SNYK_API_TOKEN.',
      inputSchema: {
        type: 'object',
        properties: {
          org_id: {
            type: 'string',
            description: 'Snyk organization UUID',
          },
          project_id: {
            type: 'string',
            description: 'Snyk project UUID',
          },
        },
        required: ['org_id', 'project_id'],
      },
      /** @param {{ org_id?: string; project_id?: string }} args */
      handler: async (args) => {
        const orgId = String(args.org_id ?? '').trim();
        const projectId = String(args.project_id ?? '').trim();
        if (!UUID_RE.test(orgId) || !UUID_RE.test(projectId)) {
          return {
            content: [
              {
                type: 'text',
                text: 'org_id and project_id must be UUIDs.',
              },
            ],
            isError: true,
          };
        }

        const projectPayload = await client.get(
          `/orgs/${orgId}/projects/${projectId}`
        );
        const projectResource = projectPayload?.data;
        const origin = projectResource?.attributes?.origin;
        if (!isGithubProjectOrigin(origin)) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    error: 'Project origin is not GitHub; no GitHub repo URL from this flow',
                    org_id: orgId,
                    project_id: projectId,
                    origin: origin ?? null,
                    hint: 'Only projects with attributes.origin === "github" expose the repo URL via the linked target.',
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          };
        }

        const targetId = targetIdFromProjectResource(projectResource);
        if (!targetId) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    error: 'GitHub project has no target relationship id',
                    org_id: orgId,
                    project_id: projectId,
                    origin,
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          };
        }

        const targetPayload = await client.get(
          `/orgs/${orgId}/targets/${targetId}`
        );
        const targetResource = targetPayload?.data;
        const url =
          typeof targetResource?.attributes?.url === 'string'
            ? targetResource.attributes.url
            : null;

        if (!url) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    error: 'Target response had no attributes.url',
                    org_id: orgId,
                    project_id: projectId,
                    target_id: targetId,
                    target: targetPayload,
                  },
                  null,
                  2
                ),
              },
            ],
            isError: true,
          };
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  url,
                  origin,
                  org_id: orgId,
                  project_id: projectId,
                  target_id: targetId,
                },
                null,
                2
              ),
            },
          ],
        };
      },
    },
  ];
}
