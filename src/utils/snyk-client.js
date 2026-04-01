/**
 * Minimal Snyk REST API client for enrichment tools.
 * @see https://docs.snyk.io/snyk-api/reference/all
 */

const DEFAULT_BASE = 'https://api.snyk.io/rest';
const API_VERSION = '2026-01-01';

export class SnykClient {
  /**
   * @param {string} apiToken
   * @param {string} [baseUrl]
   */
  constructor(apiToken, baseUrl = DEFAULT_BASE) {
    if (!apiToken?.trim()) {
      throw new Error('SNYK_API_TOKEN is required');
    }
    this.apiToken = apiToken.trim();
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.version = API_VERSION;
  }

  /**
   * @param {string} method
   * @param {string} pathWithQuery path starting with /, may include ?query
   * @returns {Promise<unknown>}
   */
  async request(method, pathWithQuery) {
    const url = `${this.baseUrl}${pathWithQuery}`;
    const headers = {
      Authorization: `token ${this.apiToken}`,
      Accept: 'application/vnd.api+json',
      'Content-Type': 'application/vnd.api+json',
      'Snyk-Version': this.version,
    };

    const response = await fetch(url, { method, headers });
    const text = await response.text();
    let body;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }

    if (!response.ok) {
      const detail =
        typeof body === 'object' && body?.errors?.[0]?.detail
          ? body.errors[0].detail
          : JSON.stringify(body);
      throw new Error(`Snyk API ${response.status}: ${detail}`);
    }

    return body;
  }

  /**
   * @param {string} path
   * @param {Record<string, string | number | boolean | undefined>} params
   */
  async get(path, params = {}) {
    const search = new URLSearchParams();
    search.set('version', this.version);
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) {
        search.set(k, String(v));
      }
    }
    const qs = search.toString();
    return this.request('GET', `${path}?${qs}`);
  }

  /**
   * Follow a pagination `links.next` URL from the API (must stay on the same API host).
   * @param {string} absoluteUrl
   */
  async getAbsolute(absoluteUrl) {
    let u;
    try {
      u = new URL(absoluteUrl);
    } catch {
      throw new Error('Invalid pagination URL from Snyk API');
    }
    const allowed = new URL(this.baseUrl);
    if (u.origin !== allowed.origin) {
      throw new Error('Refusing to follow pagination URL with unexpected origin');
    }
    const pathWithQuery = `${u.pathname}${u.search}`;
    return this.request('GET', pathWithQuery);
  }
}
