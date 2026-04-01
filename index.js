#!/usr/bin/env node
/**
 * Snyk Enrichment MCP Server — org slug resolution and org issue details for Jira workflows.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { SnykClient } from './src/utils/snyk-client.js';
import { createEnrichmentTools } from './src/tools/enrichment.js';

const token = process.env.SNYK_API_TOKEN;
const baseUrl = process.env.SNYK_API_URL;

let client;
try {
  client = new SnykClient(token, baseUrl);
} catch (e) {
  console.error(String(e?.message ?? e));
  process.exit(1);
}

const tools = createEnrichmentTools(client);

const server = new Server(
  { name: 'snyk-enrichment', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const name = request.params.name;
  const args = request.params.arguments ?? {};
  const tool = tools.find((t) => t.name === name);
  if (!tool) {
    return {
      content: [{ type: 'text', text: `Unknown tool: ${name}` }],
      isError: true,
    };
  }
  try {
    return await tool.handler(args);
  } catch (err) {
    return {
      content: [
        {
          type: 'text',
          text: String(err?.message ?? err),
        },
      ],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
