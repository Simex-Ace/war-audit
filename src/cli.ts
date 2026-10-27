#!/usr/bin/env node
/**
 * war-audit CLI — scan a browser extension's manifest.json for
 * web_accessible_resources / externally_connectable exposure risk.
 *
 * Usage:
 *   war-audit <path-to-manifest.json>
 *   war-audit <path-to-extension-dir>      # finds manifest.json inside
 */
import { readFileSync, existsSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { analyzeManifest, Finding } from './analyzer.js';

function findManifest(target: string): string {
  if (existsSync(target) && statSync(target).isDirectory()) {
    const candidate = join(target, 'manifest.json');
    if (existsSync(candidate)) return candidate;
    throw new Error(`No manifest.json found in directory: ${target}`);
  }
  return target;
}

function formatFinding(f: Finding): string {
  const icon = f.risk === 'high' ? 'HIGH' : f.risk.toUpperCase();
  const color = f.risk === 'high' ? '\x1b[31m' : '\x1b[33m';
  const reset = '\x1b[0m';
  const lines = [
    `${color}[${icon}]${reset} ${f.type}`,
    `  ${f.description}`,
  ];
  if (f.suggestion) lines.push(`  \x1b[32m→ ${f.suggestion}${reset}`);
  return lines.join('\n');
}

function main(): void {
  const target = process.argv[2];
  if (!target) {
    console.error('Usage: war-audit <manifest.json | extension-dir>');
    process.exit(2);
  }

  let manifestPath: string;
  try {
    manifestPath = findManifest(resolve(target));
  } catch (err) {
    console.error((err as Error).message);
    process.exit(2);
  }

  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    console.error(`Failed to parse ${manifestPath}: ${(err as Error).message}`);
    process.exit(2);
  }

  const findings = analyzeManifest(manifest);

  if (findings.length === 0) {
    console.log('\x1b[32m✓ No web-accessible-resource exposure risk detected.\x1b[0m');
    process.exit(0);
  }

  console.log(`\nFound ${findings.length} finding(s) in ${manifestPath}:\n`);
  for (const f of findings) {
    console.log(formatFinding(f));
    console.log('');
  }

  const hasHigh = findings.some((f) => f.risk === 'high');
  process.exit(hasHigh ? 1 : 0);
}

main();
