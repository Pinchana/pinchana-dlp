# Security model

Cookie plaintext exists only in the unlocked browser session and the assigned ephemeral worker. The Next.js proxy, Pinchana gateway, Redis, API logs, and persistent job directories must never receive it.

This protects against passive storage compromise and prevents one worker from receiving another job's cookies. It does not protect against XSS, malicious browser extensions, a compromised client, container/runtime compromise, or a malicious instance operator. Docker daemon access remains host-equivalent and is isolated to the orchestrator.

Controls include gateway service authentication, session-derived job ownership, per-job worker credentials, one-time submission, strict state transitions, key/job expiry, request/ciphertext/rate/concurrency/output/time limits, public-URL checks, fixed quality values, sanitized errors, RAM-backed cookie storage, read-only worker roots, and cleanup after exit/expiry.

Never enable DLP without strong independent values for `DLP_GATEWAY_TOKEN`, `DLP_OWNER_SECRET`, and `DLP_REDIS_PASSWORD`. Do not expose DLP API, Redis, the orchestrator, the Docker socket, or worker networks publicly.
