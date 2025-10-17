This fictional challenge helps us
understand how you reason about platform architecture and design across
both blockchain and non-blockchain parts of a developer platform.
Objective

Demonstrate strong architectural decision-making and design skills across
an API gateway surface and a minimal on-chain interface. We are looking for
signals in API governance, security-by-default, reliability thinking, and
usage metering literacy. Success is a coherent, well-argued solution with
crisp decisions and a clear, concrete API specification.
The task Scenario

You have been asked to define the architecture for a new (fictional) "Zama
Jobs API". This service allows developers to submit long-running,
asynchronous jobs via a REST API, with the final confirmation recorded on
an EVM-compatible blockchain. Your task is to define the API contract,
gateway policies, on-chain interface, and backend logic.
Deliverables

You will produce a design-led submission. Implementation is optional and
small artefacts are welcome as supporting evidence only.

A. Architecture Decision Pack

Write an Architecture Decision Record (ADR) style note that states the
problem, options considered, the chosen approach, and explicit trade-offs
covering:

    API Governance: The shape of the REST API endpoint(s) for this API, including a versioning strategy, a clear error model, and a robust idempotency strategy.
    Platform Policies: The gateway policies for authentication, per-tenant rate limits and quotas, and abuse protections.
    Metering Logic: A description of the minimal usage events that need to be captured to power a usage-based billing system, and how they map to a simple invoice.

To make your approach concrete, you must also provide:

    A concise OpenAPI specification for the REST API endpoint(s), including example requests, success responses, and error responses.

B. System Interface & Logic Design

In a separate section of your design document, describe the interfaces and
core logic for the system's key components. You should use prose,
pseudocode, or interface definitions.

    On-Chain Interface: Describe the function(s) and event(s) for a simple EVM smart contract that records the final confirmation of a job. Your description must address how to prevent replay attacks (e.g., confirming the same job twice) and what access control is necessary (i.e., who should be allowed to confirm jobs).
    API Handler Logic: Describe the sequence of steps and the core logic for the backend API handler. Your description must cover input validation, state management for the job, and how it implements the error model defined in your OpenAPI spec.

C. Reliability & Security Notes

In the final section of your design document, briefly cover:

    Reliability: Define criteria for success rate and p95 latency for the REST API endpoint(s) and describe a simple error budget policy.
    Security: Describe your chosen authentication method, the token lifecycle (expiry, rotation), and how you would enforce least-privilege access for this endpoint.

Constraints

This is a design-led exercise. Coding is optional and must remain small and
local or public testnet only. All concepts should be suitable for a local
or emulated environment. Do not use or reference any production cloud
resources, secrets, or internal company systems.
Reflection

In your design document, please include answers to these two questions:

    If I had more time: What is the one area of this design you would flesh out in more detail, and why?
    AI coding assistance: If you used tools like Copilot or ChatGPT to help generate the OpenAPI spec or other parts of the design, what worked well and what did not?

Time and scope

You have one week to submit. We do not expect you to spend the full week. A
few focused hours is fine. Prioritise clarity, completeness, and the
rationale behind your pragmatic design choices.
Submission

Please provide the following in a single Git repository (public if
possible):

    A README.md file that gives a brief overview of your submission.
    A single, comprehensive DESIGN.md or ADR.md file containing your Architecture Decision Pack, System Interface & Logic Design, Reliability & Security Notes, and answers to the reflection questions.
    The openapi.yml (or .json) file for your API specification.