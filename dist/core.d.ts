export declare const VERSION = "0.1.0";
export declare const MAX_EVIDENCE_BYTES = 1048576;
export declare const TELEMETRY_PATH = "cybermin/telemetry";
export declare const ATTESTATION_PATH = "iso-mincheck/evaluate";
export declare class AgentError extends Error {
    readonly code: string;
    readonly exitCode: number;
    constructor(code: string, message: string, exitCode?: number);
}
export interface TelemetryInput {
    orgSlug: string;
    assetId: string;
    controlId: string;
    maturity: number;
}
export interface EvidenceSubmission {
    schemaVersion: '1.0';
    orgSlug: string;
    standard: string;
    evidence: {
        sha256: string;
        byteLength: number;
        mediaType: 'application/json' | 'application/yaml';
        topLevelKeys: string[];
    };
}
export interface AttestationReceipt {
    schemaVersion: '1.0';
    attestation: {
        receiptId: string;
        orgSlug: string;
        standard: string;
        evidenceSha256: string;
        evidenceByteLength: number;
        receivedAt: string;
        status: 'RECEIVED_NOT_CERTIFIED';
    };
    proof: {
        keyId: string;
        algorithm: 'ECDSA_SHA_256';
        signature: string;
        publicKeySpki: string;
    };
    publicVerification: {
        attestationId: string;
        path: string;
        url?: string;
    };
}
export declare function validateOrgSlug(value: string): string;
export declare function createTelemetryPayload(input: TelemetryInput, now?: Date): Record<string, unknown>;
export declare function createEvidenceSubmission(filePath: string, orgSlug: string, standard: string): Promise<EvidenceSubmission>;
export declare function canonicalJson(value: unknown): string;
export declare function verifyAttestationReceipt(value: unknown): AttestationReceipt;
export declare function resolveEndpoint(baseOrEndpoint: string, operationPath: string): URL;
export declare function postJson(endpoint: URL, apiKey: string, body: unknown, timeoutMs?: number, fetchImpl?: typeof fetch): Promise<unknown>;
