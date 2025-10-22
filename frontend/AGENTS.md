# Repository Guidelines

## Build, Test, and Development Commands
Run `npm install` before contributing. Use `npm test` to execute the Vitest suite; it auto-picks up `*.test.ts` files such as `banking/banking.test.ts`. When developing new flows, keep a test watcher running via `npx vitest --watch` to catch regressions early.

## Coding Style & Naming Conventions
Author TypeScript 5.8+ code with strict typings and no `any`, aligning with `CONVENTIONS.md`. Prefer `const` and pure functions where possible. Follow the existing two-space indentation, trailing commas, and double-quoted imports visible in `banking/*.ts`. Create new modules using PascalCase type names (`WithdrawalRequest`) and camelCase functions (`processWithdrawal`). Keep files focused: domain logic in `banking/`, supporting data or prompts in their respective folders.

## Testing Guidelines
Vitest is the single source of truth. Mirror the `describe`/`it` nesting from `banking/banking.test.ts`, and name new specs `<feature>.test.ts` beside the code they verify. Cover both happy paths and error codes (e.g., `INVALID_AMOUNT`, `ACCOUNT_NOT_FOUND`). When adding behaviours, extend the spec in `banking-spec.md` and ensure corresponding tests assert messages and codes explicitly.

