import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname } from 'node:path';
import { parse as parseYaml } from 'yaml';
export const VERSION = '0.1.0';
export const MAX_EVIDENCE_BYTES = 1_048_576;
export const TELEMETRY_PATH = 'cybermin/telemetry';
export const ATTESTATION_PATH = 'iso-mincheck/evaluate';
export class AgentError extends Error {
    code;
    exitCode;
    constructor(code, message, exitCode = 1) {
        super(message);
        this.code = code;
        this.exitCode = exitCode;
        this.name = 'AgentError';
    }
}
function required(value, label) {
    const normalized = value?.trim();
    if (!normalized)
        throw new AgentError('INVALID_ARGUMENT', `${label} is required.`);
    return normalized;
}
export function validateOrgSlug(value) {
    const normalized = required(value, 'Organization slug');
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(normalized)) {
        throw new AgentError('INVALID_ARGUMENT', 'Organization slug must be 1-63 lowercase letters, digits, or internal hyphens.');
    }
    return normalized;
}
function validateIdentifier(value, label) {
    const normalized = required(value, label);
    if (normalized.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(normalized)) {
        throw new AgentError('INVALID_ARGUMENT', `${label} must be 1-128 safe identifier characters.`);
    }
    return normalized;
}
export function createTelemetryPayload(input, now = new Date()) {
    if (!Number.isInteger(input.maturity) || input.maturity < 1 || input.maturity > 5) {
        throw new AgentError('INVALID_ARGUMENT', 'Maturity must be an integer from 1 through 5.');
    }
    return {
        schemaVersion: '1.0',
        orgSlug: validateOrgSlug(input.orgSlug),
        assetId: validateIdentifier(input.assetId, 'Asset ID'),
        controlId: validateIdentifier(input.controlId, 'Control ID'),
        maturity: input.maturity,
        observedAt: now.toISOString(),
    };
}
function assertSafeEvidence(value, depth = 0) {
    if (depth > 8)
        throw new AgentError('INVALID_EVIDENCE', 'Evidence nesting exceeds eight levels.');
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return;
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new AgentError('INVALID_EVIDENCE', 'Evidence contains a non-finite number.');
        return;
    }
    if (Array.isArray(value)) {
        if (value.length > 1_000)
            throw new AgentError('INVALID_EVIDENCE', 'Evidence array exceeds 1,000 items.');
        value.forEach((item) => assertSafeEvidence(item, depth + 1));
        return;
    }
    if (typeof value !== 'object')
        throw new AgentError('INVALID_EVIDENCE', 'Evidence contains an unsupported value.');
    const entries = Object.entries(value);
    if (entries.length > 1_000)
        throw new AgentError('INVALID_EVIDENCE', 'Evidence object exceeds 1,000 fields.');
    for (const [key, item] of entries) {
        if (key.length === 0 || key.length > 128 || key === '__proto__' || key === 'prototype' || key === 'constructor') {
            throw new AgentError('INVALID_EVIDENCE', 'Evidence contains an unsafe or oversized field name.');
        }
        assertSafeEvidence(item, depth + 1);
    }
}
export async function createEvidenceSubmission(filePath, orgSlug, standard) {
    const data = await readFile(required(filePath, 'Evidence file'));
    if (data.length === 0 || data.length > MAX_EVIDENCE_BYTES) {
        throw new AgentError('INVALID_EVIDENCE', `Evidence must be between 1 and ${MAX_EVIDENCE_BYTES} bytes.`);
    }
    const extension = extname(filePath).toLowerCase();
    if (!['.json', '.yaml', '.yml'].includes(extension)) {
        throw new AgentError('INVALID_EVIDENCE', 'Evidence must use a .json, .yaml, or .yml extension.');
    }
    let parsed;
    try {
        parsed = extension === '.json' ? JSON.parse(data.toString('utf8')) : parseYaml(data.toString('utf8'), { maxAliasCount: 0 });
    }
    catch {
        throw new AgentError('INVALID_EVIDENCE', 'Evidence is not valid JSON or YAML.');
    }
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
        throw new AgentError('INVALID_EVIDENCE', 'Evidence root must be a non-empty object.');
    }
    assertSafeEvidence(parsed);
    const topLevelKeys = Object.keys(parsed).sort();
    if (topLevelKeys.length === 0)
        throw new AgentError('INVALID_EVIDENCE', 'Evidence root must be a non-empty object.');
    const standardLabel = required(standard, 'Standard');
    if (standardLabel.length > 128)
        throw new AgentError('INVALID_ARGUMENT', 'Standard must be 1-128 characters.');
    return {
        schemaVersion: '1.0',
        orgSlug: validateOrgSlug(orgSlug),
        standard: standardLabel,
        evidence: {
            sha256: createHash('sha256').update(data).digest('hex'),
            byteLength: data.length,
            mediaType: extension === '.json' ? 'application/json' : 'application/yaml',
            topLevelKeys,
        },
    };
}
export function canonicalJson(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalJson).join(',')}]`;
    return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
}
function isReceipt(value) {
    if (!value || typeof value !== 'object')
        return false;
    const receipt = value;
    return receipt.schemaVersion === '1.0' && receipt.attestation?.status === 'RECEIVED_NOT_CERTIFIED'
        && typeof receipt.proof?.signature === 'string' && typeof receipt.proof.publicKeySpki === 'string'
        && receipt.proof.algorithm === 'ECDSA_SHA_256' && typeof receipt.proof.keyId === 'string'
        && receipt.publicVerification?.attestationId === receipt.attestation.receiptId
        && receipt.publicVerification.path === `/verify/${receipt.attestation.receiptId}`
        && (receipt.publicVerification.url === undefined || receipt.publicVerification.url.endsWith(receipt.publicVerification.path));
}
export function verifyAttestationReceipt(value) {
    if (!isReceipt(value))
        throw new AgentError('INVALID_RECEIPT', 'Server returned an invalid attestation receipt.');
    try {
        const publicKey = createPublicKey({ key: Buffer.from(value.proof.publicKeySpki, 'base64'), format: 'der', type: 'spki' });
        const valid = verifySignature('sha256', Buffer.from(canonicalJson(value.attestation)), publicKey, Buffer.from(value.proof.signature, 'base64'));
        if (!valid)
            throw new Error('invalid signature');
    }
    catch {
        throw new AgentError('INVALID_RECEIPT_SIGNATURE', 'Attestation receipt signature verification failed.');
    }
    return value;
}
export function resolveEndpoint(baseOrEndpoint, operationPath) {
    let url;
    try {
        url = new URL(required(baseOrEndpoint, 'API endpoint'));
    }
    catch {
        throw new AgentError('INVALID_ENDPOINT', 'API endpoint must be an absolute URL.');
    }
    const local = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
        throw new AgentError('INVALID_ENDPOINT', 'API endpoint must use HTTPS (HTTP is allowed only for local tests).');
    }
    if (!url.pathname.replace(/^\//, '').endsWith(operationPath)) {
        url.pathname = `${url.pathname.replace(/\/$/, '')}/${operationPath}`;
    }
    url.search = '';
    url.hash = '';
    return url;
}
export async function postJson(endpoint, apiKey, body, timeoutMs = 15_000, fetchImpl = fetch) {
    if (!/^ms_live_[A-Za-z0-9_-]{20,}$/.test(required(apiKey, 'MINSTANDARD_API_KEY'))) {
        throw new AgentError('INVALID_API_KEY', 'MINSTANDARD_API_KEY has an invalid format.');
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 60_000) {
        throw new AgentError('INVALID_ARGUMENT', 'Timeout must be an integer from 1000 through 60000 milliseconds.');
    }
    let response;
    try {
        response = await fetchImpl(endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'user-agent': `minstandard-agent/${VERSION}`, 'x-api-key': apiKey },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(timeoutMs),
        });
    }
    catch {
        throw new AgentError('NETWORK_ERROR', 'Unable to reach the MinStandard API.');
    }
    let result;
    try {
        result = await response.json();
    }
    catch {
        result = undefined;
    }
    if (!response.ok) {
        const candidate = result && typeof result === 'object' ? result : {};
        const code = typeof candidate.code === 'string' ? candidate.code : `HTTP_${response.status}`;
        const message = typeof candidate.message === 'string' ? candidate.message : `MinStandard API returned HTTP ${response.status}.`;
        throw new AgentError(code, message, code === 'THRESHOLD_BREACH' ? 2 : 1);
    }
    return result;
}
