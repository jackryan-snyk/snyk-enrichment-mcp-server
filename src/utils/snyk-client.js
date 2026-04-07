/**
 * Minimal Snyk REST API client for enrichment tools.
 * @see https://docs.snyk.io/snyk-api/reference/all
 */

const DEFAULT_BASE = 'https://api.snyk.io/rest';

/**
 * Snyk REST `version` query param and `Snyk-Version` header use a calendar date (YYYY-MM-DD).
 * Using the current date at request time avoids hard-coding a version that may lag Snyk releases.
 * @param {Date} [when] Defaults to now (e.g. for tests).
 * @returns {string}
 */
export function getSnykRestApiVersionDate(when = new Date()) {
  const y = when.getFullYear();
  const m = String(when.getMonth() + 1).padStart(2, '0');
  const d = String(when.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

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
  }

  /**
   * @param {string} method
   * @param {string} pathWithQuery path starting with /, may include ?query
   * @param {{ version?: string }} [opts]
   * @returns {Promise<unknown>}
   */
  async request(method, pathWithQuery, opts = {}) {
    const version = opts.version ?? getSnykRestApiVersionDate();
    const url = `${this.baseUrl}${pathWithQuery}`;
    const headers = {
      Authorization: `token ${this.apiToken}`,
      Accept: 'application/vnd.api+json',
      'Content-Type': 'application/vnd.api+json',
      'Snyk-Version': version,
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
   * @param {{ version?: string }} [opts] Override REST `version` query and `Snyk-Version` header (defaults to today's date via {@link getSnykRestApiVersionDate}).
   */
  async get(path, params = {}, opts = {}) {
    const version = opts.version ?? getSnykRestApiVersionDate();
    const search = new URLSearchParams();
    search.set('version', version);
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) {
        search.set(k, String(v));
      }
    }
    const qs = search.toString();
    return this.request('GET', `${path}?${qs}`, { version });
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
    const v = u.searchParams.get('version');
    return this.request('GET', pathWithQuery, v ? { version: v } : {});
  }
}
