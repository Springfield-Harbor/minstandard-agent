# @minstandard/agent

Enterprise CI client for MinStandard telemetry and signed evidence receipts. The client sends only a small structured maturity observation or a local evidence digest/manifest. It never uploads the evidence file itself.

This package does not evaluate or certify conformity with CMMC, NIST CSF, ISO/IEC 42001, ISO/IEC 27001, IEC 62304, or ISO 14971. A signed receipt proves that the configured MinStandard deployment received a named file digest at a time; it is not a certification or audit opinion. The verified artifact includes a `publicVerification.path` for the separately signed redacted statement; the client rejects a path whose ID does not match the signed private receipt.

Use a pinned package version and provide secrets through CI-protected environment variables:

```sh
export MINSTANDARD_API_KEY='ms_live_replace_with_provisioned_value'
export MINSTANDARD_API_URL='https://your-api-id.execute-api.us-east-1.amazonaws.com/v1/'
npx @minstandard/agent@0.1.0 --version
```

See `docs/ENTERPRISE_ONBOARDING.md` in the MinStandard repository for provisioning, SAML, pipeline, and operational instructions.
