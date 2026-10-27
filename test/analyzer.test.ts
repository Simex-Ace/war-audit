import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeManifest } from '../src/analyzer.ts';

test('flags WAR exposed to <all_urls> as broad-exposure', () => {
  const manifest = {
    manifest_version: 3,
    web_accessible_resources: [{ resources: ['injected.js'], matches: ['<all_urls>'] }],
  };
  const findings = analyzeManifest(manifest);
  const broad = findings.find((f) => f.type === 'broad-exposure');
  assert.ok(broad);
  assert.equal(broad.risk, 'high');
});

test('flags JS resources as sensitive-resource', () => {
  const manifest = {
    manifest_version: 3,
    web_accessible_resources: [
      { resources: ['bridge.js'], matches: ['https://trusted.example.com/*'] },
    ],
  };
  const findings = analyzeManifest(manifest);
  const sensitive = findings.find((f) => f.type === 'sensitive-resource');
  assert.ok(sensitive);
  assert.equal(sensitive.risk, 'high');
});

test('does NOT flag static images as sensitive', () => {
  const manifest = {
    manifest_version: 3,
    web_accessible_resources: [{ resources: ['logo.png'], matches: ['<all_urls>'] }],
  };
  const findings = analyzeManifest(manifest);
  assert.equal(findings.some((f) => f.type === 'sensitive-resource'), false);
});

test('treats MV2 string[] WAR as exposed to all origins', () => {
  const manifest = {
    manifest_version: 2,
    web_accessible_resources: ['injected.js'],
  };
  const findings = analyzeManifest(manifest);
  assert.ok(findings.some((f) => f.type === 'broad-exposure'));
  assert.ok(findings.some((f) => f.type === 'sensitive-resource'));
});

test('flags broad externally_connectable matches', () => {
  const manifest = {
    manifest_version: 3,
    externally_connectable: { matches: ['*://*/*'] },
  };
  const findings = analyzeManifest(manifest);
  const broad = findings.find((f) => f.type === 'broad-connectable');
  assert.ok(broad);
  assert.equal(broad.risk, 'medium');
});

test('returns no findings for a clean manifest', () => {
  const manifest = { manifest_version: 3, permissions: ['storage', 'alarms'] };
  assert.deepEqual(analyzeManifest(manifest), []);
});

test('returns no findings for narrowly scoped static WAR', () => {
  const manifest = {
    manifest_version: 3,
    web_accessible_resources: [{ resources: ['icon.png'], matches: ['https://a.example.com/*'] }],
  };
  assert.deepEqual(analyzeManifest(manifest), []);
});
