#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { mkdir } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { AgentError, ATTESTATION_PATH, TELEMETRY_PATH, VERSION, createEvidenceSubmission, createTelemetryPayload, postJson, resolveEndpoint, verifyAttestationReceipt, } from './core.js';
const HELP = `Usage: minstandard-agent <command> [options]

Commands:
  push-telemetry  Submit a framework control maturity observation
  iso-mincheck    Validate and hash evidence, then request a signed receipt

Shared environment:
  MINSTANDARD_API_KEY  Required secret; command-line API keys are intentionally unsupported
  MINSTANDARD_API_URL  Required API base URL unless --endpoint is supplied

Run minstandard-agent <command> --help for command options.`;
function parseNumber(value, label) {
    if (!value || !/^\d+$/.test(value))
        throw new AgentError('INVALID_ARGUMENT', `${label} must be an integer.`);
    return Number(value);
}
async function pushTelemetry(args) {
    const parsed = parseArgs({ args, strict: true, allowPositionals: false, options: {
            help: { type: 'boolean', short: 'h' }, endpoint: { type: 'string' }, org: { type: 'string' },
            asset: { type: 'string' }, control: { type: 'string' }, maturity: { type: 'string' }, timeout: { type: 'string' },
        } });
    if (parsed.values.help) {
        process.stdout.write('Usage: minstandard-agent push-telemetry --org <slug> --asset <id> --control <id> --maturity <1-5> [--endpoint <url>]\n');
        return;
    }
    const payload = createTelemetryPayload({
        orgSlug: parsed.values.org ?? '', assetId: parsed.values.asset ?? '', controlId: parsed.values.control ?? '',
        maturity: parseNumber(parsed.values.maturity, 'Maturity'),
    });
    const endpoint = resolveEndpoint(parsed.values.endpoint ?? process.env.MINSTANDARD_API_URL ?? '', TELEMETRY_PATH);
    const result = await postJson(endpoint, process.env.MINSTANDARD_API_KEY ?? '', payload, parsed.values.timeout ? parseNumber(parsed.values.timeout, 'Timeout') : undefined);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
async function isoMincheck(args) {
    const parsed = parseArgs({ args, strict: true, allowPositionals: false, options: {
            help: { type: 'boolean', short: 'h' }, endpoint: { type: 'string' }, org: { type: 'string' },
            standard: { type: 'string' }, 'evidence-file': { type: 'string' }, 'output-artifact': { type: 'string' }, timeout: { type: 'string' },
        } });
    if (parsed.values.help) {
        process.stdout.write('Usage: minstandard-agent iso-mincheck --org <slug> --standard <label> --evidence-file <json|yaml> [--output-artifact <json>] [--endpoint <url>]\n');
        return;
    }
    const submission = await createEvidenceSubmission(parsed.values['evidence-file'] ?? '', parsed.values.org ?? '', parsed.values.standard ?? '');
    const endpoint = resolveEndpoint(parsed.values.endpoint ?? process.env.MINSTANDARD_API_URL ?? '', ATTESTATION_PATH);
    const result = await postJson(endpoint, process.env.MINSTANDARD_API_KEY ?? '', submission, parsed.values.timeout ? parseNumber(parsed.values.timeout, 'Timeout') : undefined);
    const receipt = verifyAttestationReceipt(result);
    if (receipt.attestation.evidenceSha256 !== submission.evidence.sha256 || receipt.attestation.orgSlug !== submission.orgSlug) {
        throw new AgentError('RECEIPT_MISMATCH', 'Signed receipt does not match the submitted organization and evidence digest.');
    }
    const output = parsed.values['output-artifact'];
    if (output) {
        const target = resolve(output);
        await mkdir(dirname(target), { recursive: true });
        await writeFile(target, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
        process.stdout.write(`Verified signed evidence receipt written to ${target}\n`);
    }
    else {
        process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
    }
}
export async function run(argv = process.argv.slice(2)) {
    const [command, ...args] = argv;
    if (!command || command === '--help' || command === '-h') {
        process.stdout.write(`${HELP}\n`);
        return;
    }
    if (command === '--version' || command === '-v') {
        process.stdout.write(`${VERSION}\n`);
        return;
    }
    if (command === 'push-telemetry')
        return pushTelemetry(args);
    if (command === 'iso-mincheck')
        return isoMincheck(args);
    throw new AgentError('UNKNOWN_COMMAND', `Unknown command: ${command}`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    run().catch((error) => {
        if (error instanceof AgentError) {
            process.stderr.write(`${error.code}: ${error.message}\n`);
            process.exitCode = error.exitCode;
            return;
        }
        process.stderr.write('UNEXPECTED_ERROR: The command failed.\n');
        process.exitCode = 1;
    });
}
