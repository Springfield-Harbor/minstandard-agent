import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  AgentError, ATTESTATION_PATH, canonicalJson, createEvidenceSubmission, createTelemetryPayload,
  postJson, resolveEndpoint, verifyAttestationReceipt,
} from '../src/core';

describe('agent protocol', () => {
  it('creates a bounded telemetry observation', () => {
    expect(createTelemetryPayload({ orgSlug: 'acme-corp', assetId: 'prod:k8s-01', controlId: 'PR.AC-3', maturity: 4 }, new Date('2026-08-01T12:00:00Z'))).toEqual({
      schemaVersion: '1.0', orgSlug: 'acme-corp', assetId: 'prod:k8s-01', controlId: 'PR.AC-3', maturity: 4, observedAt: '2026-08-01T12:00:00.000Z',
    });
    expect(() => createTelemetryPayload({ orgSlug: 'ACME', assetId: 'asset', controlId: 'control', maturity: 6 })).toThrow(AgentError);
  });

  it('validates JSON/YAML locally and submits only a digest manifest', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'minstandard-agent-'));
    const jsonPath = join(directory, 'evidence.json');
    const yamlPath = join(directory, 'evidence.yaml');
    await writeFile(jsonPath, '{"model":"abc","passed":true}');
    await writeFile(yamlPath, 'model: abc\npassed: true\n');
    const json = await createEvidenceSubmission(jsonPath, 'acme-corp', 'ISO/IEC 42001:2023');
    const yaml = await createEvidenceSubmission(yamlPath, 'acme-corp', 'ISO/IEC 42001:2023');
    expect(json.evidence).toEqual(expect.objectContaining({ byteLength: 29, mediaType: 'application/json', topLevelKeys: ['model', 'passed'] }));
    expect(json.evidence.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(json)).not.toContain('abc');
    expect(yaml.evidence).toEqual(expect.objectContaining({ mediaType: 'application/yaml', topLevelKeys: ['model', 'passed'] }));
  });

  it('verifies a KMS-compatible ECDSA receipt and rejects tampering', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const attestation = {
      receiptId: 'receipt-1', orgSlug: 'acme-corp', standard: 'ISO/IEC 42001:2023', evidenceSha256: 'a'.repeat(64),
      evidenceByteLength: 29, receivedAt: '2026-08-01T12:00:00.000Z', status: 'RECEIVED_NOT_CERTIFIED' as const,
    };
    const receipt = {
      schemaVersion: '1.0' as const, attestation,
      proof: {
        keyId: 'kms-key-id', algorithm: 'ECDSA_SHA_256' as const,
        signature: sign('sha256', Buffer.from(canonicalJson(attestation)), privateKey).toString('base64'),
        publicKeySpki: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      },
      publicVerification: { attestationId: 'receipt-1', path: '/verify/receipt-1' },
    };
    expect(verifyAttestationReceipt(receipt)).toEqual(receipt);
    expect(() => verifyAttestationReceipt({ ...receipt, attestation: { ...attestation, orgSlug: 'other-org' } })).toThrowError(/signature verification failed/);
    expect(() => verifyAttestationReceipt({ ...receipt, publicVerification: { attestationId: 'receipt-2', path: '/verify/receipt-2' } })).toThrowError(/invalid attestation receipt/i);
  });

  it('requires HTTPS except localhost and maps threshold errors to exit code 2', async () => {
    expect(resolveEndpoint('https://api.example.test/v1/', ATTESTATION_PATH).href).toBe('https://api.example.test/v1/iso-mincheck/evaluate');
    expect(() => resolveEndpoint('http://api.example.test', ATTESTATION_PATH)).toThrowError(/HTTPS/);
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ code: 'THRESHOLD_BREACH', message: 'Below configured threshold.' }), { status: 422, headers: { 'content-type': 'application/json' } }));
    await expect(postJson(new URL('https://api.example.test/v1/cybermin/telemetry'), `ms_live_${'a'.repeat(24)}`, {}, 1_000, fetchImpl)).rejects.toEqual(expect.objectContaining({ code: 'THRESHOLD_BREACH', exitCode: 2 }));
    expect(fetchImpl).toHaveBeenCalledWith(expect.any(URL), expect.objectContaining({ headers: expect.objectContaining({ 'x-api-key': `ms_live_${'a'.repeat(24)}` }) }));
  });
});
