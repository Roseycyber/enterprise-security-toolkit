# AI Governance & AI Risk Assessment (ISO 42001 / NIST AI RMF)

## Why this document exists

AI systems introduce risks that traditional information-security frameworks
were not designed to capture: model behavior risk, training-data provenance,
bias and fairness, prompt injection, and opaque third-party AI supply chains.
This document extends the risk assessment framework in doc 01 to cover AI
systems, aligned to **ISO/IEC 42001:2023** (AI Management Systems) and the
**NIST AI Risk Management Framework (AI RMF 1.0)**.

## Framework alignment

| Framework | Role in this process |
|---|---|
| ISO/IEC 42001 | Management-system layer: AI policy, roles, impact assessment, lifecycle controls |
| NIST AI RMF | Risk process layer: Govern / Map / Measure / Manage functions |
| ISO/IEC 27001 | Underlying information-security controls AI systems still depend on |
| EU AI Act (where applicable) | Regulatory classification of AI use cases by risk tier |

## AI system intake — extending the risk assessment

Any project introducing an AI component (in-house model, fine-tuned model,
or third-party AI service such as an LLM API) goes through the standard
risk assessment (doc 01) **plus** an AI impact assessment covering:

1. **Purpose & classification** — what decision or output does the AI
   produce, and does it affect individuals (hiring, credit, access)?
   Higher human impact = higher inherent risk tier.
2. **Data provenance** — what data trains or grounds the system? Is
   personal data involved (GDPR interaction)? Is the training data's
   licensing and consent status known?
3. **Model behavior risks** — hallucination/inaccuracy tolerance for the
   use case, bias testing approach, and defined accuracy thresholds.
4. **Security-specific AI threats** — prompt injection, training-data
   poisoning, model extraction, and sensitive-data leakage through
   model outputs. These map onto the STRIDE analysis in doc 03:
   prompt injection is a *tampering/elevation* threat; output leakage
   is *information disclosure*.
5. **Human oversight** — is there a human in the loop for consequential
   decisions? Who can override the system, and is that override logged?
6. **Third-party AI supply chain** — an external AI provider is a vendor
   and goes through the TPRM process (doc 04) with additional questions:
   Is customer data used for training? What is the data-retention policy?
   Where is inference performed (data residency)?

## AI-specific additions to the vendor risk assessment

When the vendor provides an AI service, append these to the standard
template (templates/vendor-risk-assessment-template.md):

- [ ] Provider commits contractually that our data is **not used to train** their models (or opt-out confirmed and evidenced)
- [ ] Model/provider documentation reviewed (model card, system card, or equivalent)
- [ ] Data residency and inference location confirmed
- [ ] Provider's approach to prompt-injection and abuse mitigation documented
- [ ] Output logging available to support auditability of AI-assisted decisions
- [ ] Sub-processor list includes any downstream model providers

## Worked example: business team wants to use an LLM to summarize customer complaints

Applying the intake above:

| Step | Finding | Action |
|---|---|---|
| Purpose | Internal summarization, no automated decisions about individuals | Lower inherent risk tier |
| Data | Complaint text contains personal data | GDPR basis confirmed; PII minimisation before sending to the API |
| Model behavior | Summaries feed weekly reports, not decisions | Accuracy spot-check process, human review before circulation |
| Security threats | Complaint text could contain adversarial content (prompt injection) | Treat model output as untrusted; no downstream automated actions from output |
| Oversight | Analyst reviews all summaries | Documented in procedure |
| Supply chain | Third-party LLM API | Full vendor assessment; no-training clause required in contract |

**Outcome**: approved with conditions — exactly the same decision pattern
as the threat-model example in doc 03, extended with AI-specific criteria.

## Monitoring AI systems in production

- AI usage inventory maintained (which systems, which models, which owners) —
  you cannot govern what you haven't mapped (NIST AI RMF "Map" function).
- Periodic re-assessment on model version changes, not just calendar cadence —
  a provider swapping the underlying model is a material change.
- AI-related incidents (data leakage via output, harmful output, injection
  attempts) feed the same incident-response and SIEM processes as doc 06.
