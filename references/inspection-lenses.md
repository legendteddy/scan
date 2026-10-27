# Inspection lenses

Select and combine lenses based on the actual artifacts. Trace connections across types.

| Target | Prioritize |
|---|---|
| Website/frontend | Pages and routes, user journeys, navigation, forms, accessibility, client/server boundaries, storage, third parties, content accuracy, performance and deployment assumptions |
| Backend/service | Request and event flows, identity/authorization, data lifecycle, validation, error recovery, persistence, jobs, integrations, observability, concurrency and deployment |
| Documents | Authorship, provenance, versions, chronology, claims and citations, contradictions, omissions, content hierarchy, linked material, confidential information and intended audience |
| APK/app/package | Manifest, permissions, signing metadata, resources, libraries, components, exposed interfaces, network configuration, update path and static-analysis limits |
| Binary | Format, architecture, headers, imports, symbols, strings with context, embedded resources, signatures, dependencies and limits of static reconstruction; never equate strings with executed behavior |
| Archive/mixed folder | Safe member inventory, nesting, duplicates, relationships, packaging completeness, provenance and unsupported/encrypted members |
| Data/model | Schemas, dimensions, splits, provenance, licenses, personal data, leakage, representativeness, quality checks, model configuration, weights format, evaluation claims and loading hazards |
| AI-generated work | Placeholder or fabricated claims, provenance gaps, disconnected components, incorrect dependencies, copied secrets, unsupported assurances, tests that merely mirror implementation and mismatch between claims and actual behavior |

Separate source evidence from packaged or deployed evidence. Report whether build reproducibility, runtime behavior, production settings, signing trust, model performance, and external services were actually verified. Do not manufacture these conclusions from source inspection.
