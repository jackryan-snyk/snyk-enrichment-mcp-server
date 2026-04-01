# Snyk Enrichment MCP Server

[MCP](https://modelcontextprotocol.io) (stdio) server for the [Snyk REST API](https://docs.snyk.io/snyk-api/reference/all). Use it to resolve organization slugs, fetch issue details, and enrich workflows that combine Snyk with tools like Jira (e.g. via the Atlassian MCP).

## Requirements

- Node.js **18+**
- A [Snyk API token](https://docs.snyk.io/snyk-api/authentication-for-api)

## Install

```bash
git clone <your-repo-url> snyk-enrichment-mcp-server
cd snyk-enrichment-mcp-server
npm install
```

## Configuration

Set **`SNYK_API_TOKEN`** in the environment. Optional: **`SNYK_API_URL`** if you use a non-default API base (defaults to `https://api.snyk.io/rest`).

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

| Tool | Purpose |
|------|---------|
| `snyk_resolve_org_id_from_slug` | Resolve org UUID from slug or `app.snyk.io` org URL |
| `snyk_get_org_issue_details` | `GET /orgs/{org_id}/issues/{issue_id}`; accepts REST UUID, full `app.snyk.io` issue links (`#issue-{uuid}`), Snyk keys / problem ids with `project_id`, or optional `match_*` heuristics for Snyk Code |

See [Issues API reference](https://docs.snyk.io/snyk-api/reference/issues).

## Scripts

- `npm start` — run the server on stdio (normally started by the MCP host, not manually for day-to-day use)

## License

MIT — see [LICENSE](LICENSE).
