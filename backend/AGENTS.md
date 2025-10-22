# Repository Guidelines

## Project Structure & Module Organization

Project consists of subprojects:
- frontend - web page of admin and user of service.
- backend - REST webservice written in RUST, which serves requests from `web-admin` and `web-user` and optionaly other clients.
- database - all files and scripts concerning database.

## Commit & Pull Request Guidelines
Follow the Conventional Commits pattern seen in history (e.g., `feat: add overdraft guard`, `chore: update prompts`). Scope commits tightly and include failing-test reproductions when fixing bugs. Pull requests should link to any tracked task, summarize behavioural changes, and attach CLI output (`npm test`) or screenshots for documentation updates. Request review from another agent when altering shared abstractions or prompts to maintain consistency.
