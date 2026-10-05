# Security model

PhishLens inspects untrusted URL strings and raster QR images on a user's own machine. A pasted URL must never cause a network request to its hostname, HTML execution, script execution, shell execution, or automatic navigation.

## Trust boundaries

- The browser's URL parser establishes URL components. Raw-text annotations are explanatory; they never override the parser's destination.
- Institution policy is local build-time configuration. Every user and department uses the same version.
- All findings are deterministic. The AI service is an optional explainer and has no authority over the verdict.
- Physical source descriptions are user-reported context, not verified claims.
- Query-string destinations are text evidence only. Server behavior remains unknown.

## Controls

- No remote runtime assets, reputation calls, submitted-host DNS checks, redirect tracing, or external speech services.
- Bounded input size, nested decoding, candidate expansion, and QR image dimensions.
- Native URL/PSL parsing, conservative fuzzy matching, exact trusted-host boundaries.
- User-controlled data rendered as text; no executable links in results.
- Local server bound to IPv4 loopback, with host/origin validation, bounded bodies, fixed Ollama upstream, timeouts, and concurrency limits.
- Security headers and Content Security Policy. No broad CORS allowance.
- Installed local generation-capable models only; cloud or remote models must be excluded.
- No raw URL logging or persistence. AI requests omit arbitrary query strings and credential values.
- Rule explanations remain available on model errors. Model output is plain text and does not control actions.

## Residual limitations

Lexical rules cannot verify a page, certificate, download, DNS state, domain ownership, reputation, compromise, or final redirect. Similarity can produce false positives and miss other visual tricks. AI text can be imperfect even after constraints and validation. A hostile process on the user's machine is outside this local-app threat model.

This implementation is a local application, not an authenticated multi-user internet service. Before institutional rollout, validate the actual official domains, evaluate local model explanations, review accessibility with real users, maintain dependencies and suffix data, and conduct an independent security review.

When reporting a defect, use synthetic `.example` inputs and include the policy version, expected parsed hostname, observed finding, and reproduction steps. Do not include real credentials or tokens.
