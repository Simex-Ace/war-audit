/**
 * Core analyzer: evaluates the security exposure introduced by a browser
 * extension's `web_accessible_resources` (WAR) and `externally_connectable`
 * declarations.
 *
 * WAR exposes extension-internal files to web pages. When combined with broad
 * match patterns (`<all_urls>`) or sensitive asset types (JS/HTML/JSON/WASM),
 * it creates an attack surface where a malicious page can read internal assets
 * and — if those assets reference privileged APIs — chain XSS into extension
 * privilege escalation.
 *
 * `externally_connectable` grants web pages the ability to message the
 * extension, which can trigger privileged `onMessageExternal` handlers.
 *
 * Sources:
 * - https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions
 * - https://developer.chrome.com/docs/extensions/reference/manifest/web-accessible-resources
 * - https://developer.chrome.com/docs/extensions/reference/manifest/externally-connectable
 */

export type RiskLevel = 'high' | 'medium' | 'low' | 'none';

export type FindingType =
  | 'broad-exposure'      // WAR exposed via <all_urls> / *://*/* etc.
  | 'sensitive-resource'  // JS/HTML/JSON/WASM assets made web-accessible
  | 'broad-connectable';  // externally_connectable open to all origins

export interface Finding {
  type: FindingType;
  risk: RiskLevel;
  description: string;
  suggestion?: string;
}

const SENSITIVE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.html', '.htm', '.json', '.wasm'];

const BROAD_MATCH_PATTERNS = ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'];

function isBroadMatch(pattern: string): boolean {
  return BROAD_MATCH_PATTERNS.includes(pattern);
}

function hasSensitiveExtension(resource: string): boolean {
  return SENSITIVE_EXTENSIONS.some((ext) => resource.toLowerCase().endsWith(ext));
}

/** Extracts `externally_connectable` from a manifest (if present). */
function getExternallyConnectable(manifest: Record<string, unknown>): {
  ids?: string[];
  matches?: string[];
} | null {
  const ec = manifest.externally_connectable as Record<string, unknown> | undefined;
  if (!ec || typeof ec !== 'object') return null;

  const asStrings = (v: unknown): string[] | undefined =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : undefined;

  return {
    ids: asStrings(ec.ids),
    matches: asStrings(ec.matches),
  };
}

function buildWarFindings(
  warEntries: Array<{ resources: string[]; matches: string[] }>,
): Finding[] {
  const findings: Finding[] = [];

  for (const { resources, matches } of warEntries) {
    const broadMatches = matches.filter(isBroadMatch);
    if (broadMatches.length > 0) {
      findings.push({
        type: 'broad-exposure',
        risk: 'high',
        description:
          `Web-accessible resources are exposed to all websites via ` +
          `${broadMatches.map((m) => `'${m}'`).join(', ')}. Any page the user visits can ` +
          `fetch these internal files, enabling fingerprinting, data extraction, or XSS-based ` +
          `privilege escalation when combined with sensitive assets.`,
        suggestion:
          'Restrict match patterns to the specific origins that genuinely need access, or use ' +
          'a narrowly scoped wildcard (e.g. a single trusted domain).',
      });
    }

    const sensitiveResources = resources.filter(hasSensitiveExtension);
    if (sensitiveResources.length > 0) {
      findings.push({
        type: 'sensitive-resource',
        risk: 'high',
        description:
          `Sensitive resource types (${sensitiveResources
            .map((r) => `'${r}'`)
            .join(', ')}) are web-accessible. Scripts and HTML files may embed ` +
          `internal logic, tokens, or DOM sinks that a hostile page can read or execute.`,
        suggestion:
          'Avoid exposing executable or data-bearing assets (JS/HTML/JSON) to web pages. ' +
          'Prefer exposing only static, non-sensitive assets such as images or fonts.',
      });
    }
  }

  return findings;
}

function buildExternallyConnectableFindings(
  externallyConnectable: { ids?: string[]; matches?: string[] } | null,
): Finding[] {
  if (!externallyConnectable) return [];

  const broadMatches = (externallyConnectable.matches ?? []).filter(isBroadMatch);
  if (broadMatches.length === 0) return [];

  return [
    {
      type: 'broad-connectable',
      risk: 'medium',
      description:
        `externally_connectable allows any website (${broadMatches
          .map((m) => `'${m}'`)
          .join(', ')}) to send messages to this extension. If an ` +
        `onMessageExternal handler performs privileged actions without validating the sender, ` +
        `any page can trigger them.`,
      suggestion:
        'Restrict externally_connectable matches to specific trusted origins and validate ' +
        '`sender.origin` / `sender.id` inside every onMessageExternal handler.',
    },
  ];
}

/**
 * Analyzes a browser extension manifest for web-accessible-resources and
 * externally-connectable exposure risk.
 */
export function analyzeManifest(manifest: Record<string, unknown>): Finding[] {
  const warEntries: Array<{ resources: string[]; matches: string[] }> = [];
  const war = manifest.web_accessible_resources;

  if (Array.isArray(war)) {
    for (const entry of war) {
      if (typeof entry === 'string') {
        // MV2: plain string list, applies to all origins.
        warEntries.push({ resources: [entry], matches: ['<all_urls>'] });
      } else if (entry && typeof entry === 'object') {
        const obj = entry as Record<string, unknown>;
        const resources = Array.isArray(obj.resources)
          ? obj.resources.filter((r): r is string => typeof r === 'string')
          : [];
        const matches = Array.isArray(obj.matches)
          ? obj.matches.filter((m): m is string => typeof m === 'string')
          : [];
        warEntries.push({ resources, matches });
      }
    }
  }

  const findings = buildWarFindings(warEntries);
  findings.push(...buildExternallyConnectableFindings(getExternallyConnectable(manifest)));

  return findings;
}
