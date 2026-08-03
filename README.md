# micro-policy

[![ci](https://github.com/cloudsforge-online/micro-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-policy/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![tests](https://img.shields.io/badge/tests-real%20Postgres-4169E1?logo=postgresql&logoColor=white)](./.github/workflows/ci.yml)

The decision service. Callers submit a subject, an action, a resource and a context, and receive
allow, deny, challenge or review with reasons and obligations. **It decides; callers enforce.**

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

It owns rules, limits, velocity counters, trusted addresses, cooling-off timers, approval
workflows, freezes, and device and account risk scores.

```
pnpm install
pnpm migrate     # a one-shot job. Never run from the service.
pnpm start
pnpm check
```

Configuration is documented in `.env.example`; every value there is a placeholder, and `src/env.ts`
refuses to boot on one.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
