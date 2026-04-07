# Snyk Enrichment MCP Server

[MCP](https://modelcontextprotocol.io) (stdio) server for the [Snyk REST API](https://docs.snyk.io/snyk-api/reference/all). Use it to resolve organization slugs, fetch issue details, resolve GitHub repository URLs for imported projects, and enrich workflows that combine Snyk with tools like Jira (e.g. via the Atlassian MCP).

> **Disclaimer:** This is not an officially supported Snyk tool and is not directly endorsed by Snyk.

## Requirements

- Node.js **18+**
- A [Snyk API token](https://docs.snyk.io/snyk-api/authentication-for-api) with access to the organizations you query

## Install

```bash
git clone <your-repo-url> snyk-enrichment-mcp-server
cd snyk-enrichment-mcp-server
npm install
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_API_TOKEN` | Yes | Snyk API token (`Authorization: token …` on REST calls) |
| `SNYK_API_URL` | No | API base URL (default: `https://api.snyk.io/rest`) |

## How the server talks to Snyk

- **Transport:** stdio ([Model Context Protocol](https://modelcontextprotocol.io)); the MCP host starts `node index.js` (or your configured command).
- **REST version:** Each request sends a `version` query parameter and a `Snyk-Version` header set to **today’s calendar date** in `YYYY-MM-DD` (local time on the machine running the server). That avoids pinning a fixed API version string. Optional per-call overrides exist in code via `SnykClient.get(…, …, { version })` if you extend the server.
- **Pagination:** When following `links.next` from list responses, the client reuses the `version` value embedded in the next URL so headers stay aligned.

## Cursor / MCP client

Point your MCP config at this server over stdio, for example:

```json
{
  "mcpServers": {
    "snyk-enrichment": {
      "command": "node",
      "args": ["/absolute/path/to/snyk-enrichment-mcp-server/index.js"],
      "env": {
        "SNYK_API_TOKEN": "your-token-here"
      }
    }
  }
}
```

Restart or reload MCP after changing configuration.

## Tools

All tools return MCP **`text`** content. Successful results are usually **pretty-printed JSON** strings. Errors set the MCP result’s **`isError`** flag where applicable and include a JSON object or plain message describing the failure.

---

### `snyk_resolve_org_id_from_slug`

Resolves a Snyk **organization UUID** from a human-readable slug or from an `app.snyk.io` URL that contains `/org/{slug}/`.

| | |
|---|---|
| **Snyk API** | [`GET /orgs?slug=…`](https://docs.snyk.io/snyk-api/reference/orgs) |
| **Arguments** | `org_slug_or_url` (string, required): slug (e.g. `my-org`) or full Snyk app URL with `/org/{slug}/` |
| **Success body** | JSON: `org_id`, `slug`, `name` |
| **Typical use** | Turn Jira / integration text or a copied Snyk URL into `org_id` for other tools |

---

### `snyk_get_org_issue_details`

Loads full issue JSON via [`GET /orgs/{org_id}/issues/{issue_id}`](https://docs.snyk.io/snyk-api/reference/issues), with flexible ways to identify the issue when Jira only has a link, a SNYK-* id, or fuzzy Snyk Code fields.

**Resolution modes (summary)**

1. **REST UUID** — `issue_id` is the issue UUID (optional `issue-` prefix). `project_id` not required.
2. **Full app link** — `issue_id` is a `app.snyk.io` URL with `/org/{slug}/`, optional `/project/{id}/`, and `#issue-{uuid}`. Org slug is resolved automatically; `org_id` / `project_id` optional when the URL supplies them.
3. **External / product id** — `issue_id` is a Snyk Code key, `SNYK-*` problem id, `key_asset`, etc. Requires **`project_id`**; the tool scans project issues until it finds a match (with optional `issue_type` filter, then a retry without type).
4. **Heuristic only (Snyk Code)** — Omit `issue_id`. Pass **`project_id`** and one or more **`match_*`** fields; **all** provided heuristics must match. If exactly one issue matches, the tool fetches that issue. If zero or many match, it returns an error JSON with details or candidate summaries.

**Arguments** (all optional unless noted by validation rules above)

| Argument | Description |
|----------|-------------|
| `org_id` | Org UUID. Omit only when `issue_id` is a full app URL that includes `/org/{slug}/`. |
| `project_id` | Project UUID. Required for non-UUID `issue_id` and for heuristic mode. |
| `issue_id` | App URL with `#issue-{uuid}`, REST UUID, Snyk key / SNYK-* / `key_asset`, etc. |
| `issue_type` | Filter for listing: `code`, `package_vulnerability`, `license`, `cloud`, `config`, `custom`. Heuristic default is `code`. |
| `match_cwe` | e.g. `CWE-89` or `89` |
| `match_risk_score` | Integer, `attributes.risk.score.value` |
| `match_title_contains` | Case-insensitive substring on title |
| `match_created_date` | `YYYY-MM-DD` vs `created_at` |
| `match_file_path_contains` | Substring inside `coordinates` (Code) |

**Success body** — JSON including `issue` (full API resource) and fields such as `resolved_rest_issue_id`, `resolution` (for heuristic single match), etc.

---

### `snyk_get_project_github_repo_url`

Returns the **Git remote URL** for a Snyk project when it is backed by **GitHub** (`attributes.origin === "github"`). Uses the linked integration **target** from the project resource.

| | |
|---|---|
| **Snyk API** | [`GET /orgs/{org_id}/projects/{project_id}`](https://docs.snyk.io/snyk-api/reference/projects), then [`GET /orgs/{org_id}/targets/{target_id}`](https://docs.snyk.io/snyk-api/reference/targets) |
| **Arguments** | `org_id` (UUID), `project_id` (UUID), both required |
| **Success body** | JSON: `url` (GitHub repo URL), `origin`, `org_id`, `project_id`, `target_id` |
| **Errors** | Non-GitHub origin, missing target relationship, or target without `attributes.url` — returned as `isError` with explanatory JSON |

**Typical workflow with Jira:** Parse `app.snyk.io/.../project/{project_id}` from the ticket → resolve slug to `org_id` with `snyk_resolve_org_id_from_slug` if you only have the slug → call `snyk_get_project_github_repo_url`.

---

## API reference quick links

- [Organizations](https://docs.snyk.io/snyk-api/reference/orgs)
- [Issues](https://docs.snyk.io/snyk-api/reference/issues)
- [Projects](https://docs.snyk.io/snyk-api/reference/projects)
- [Targets](https://docs.snyk.io/snyk-api/reference/targets)

## Scripts

- `npm start` — run the server on stdio (normally started by the MCP host, not manually for day-to-day use)

## License

MIT — see [LICENSE](LICENSE).
