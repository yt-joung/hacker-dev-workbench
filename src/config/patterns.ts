export interface SecretPattern {
  name: string;
  regex: RegExp;
}

export const VULN_PATTERNS: SecretPattern[] = [
  {
    name: 'API Key/Secret',
    regex: /(?:api_key|apikey|key|secret|token|password|auth)[\s:]*["']([^"']{8,})["']/gi
  },
  {
    name: 'Internal Endpoint',
    regex: /https?:\/\/(?:[a-z0-9-]+\.)*internal[a-z0-9.-]*/gi
  },
  {
    name: 'Developer Comment',
    regex: /\/\/\s*(TODO|FIXME|HACK|DEBUG|DEV|STAGING).*/gi
  },
  {
    name: 'IP/Domain Pattern',
    regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
  }
];
