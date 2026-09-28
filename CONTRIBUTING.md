# Contributing to TokenTimer

Thank you for your interest in contributing to TokenTimer!

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install dependencies: `pnpm install`
4. Set up your environment: copy `.env.example` files and configure

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed local setup instructions.
See [QUICKSTART.md](QUICKSTART.md) for deployment options.

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Run the quality checks:
   ```bash
   pnpm run lint
   pnpm run build
   pnpm run test:contracts
   ```
   If the dashboard is affected, also run the relevant Prettier checks.
   For a complete pre-merge validation, you can run:
   ```bash
   pnpm run test:ci
   ```
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/) format:
   ```
   feat(core-api): add new endpoint for X
   fix(core-ui): resolve rendering issue in Y
   ```
5. Open a Pull Request against `main`

### Maintainer pre-merge validation

Contributor pull-request Actions are intentionally disabled to avoid executing untrusted contributor code in GitHub Actions.

Local validation is the normal pre-merge path. Maintainers should run the relevant local checks before merging. For a complete validation, `pnpm run test:ci` can be used.

A maintainer may use `workflow_dispatch` for a validation run only when the selected code/ref has already been reviewed and is considered trusted. It must not be used to execute unreviewed contributor code.

After a change is merged, the push CI run on `main` remains the authoritative post-merge validation and must be green before a release.

## Code Style

- Follow existing patterns in the codebase
- Use `camelCase` for variables and functions
- Use `PascalCase` for components and classes
- Use `kebab-case` for file and directory names
- Use `UPPER_CASE` for constants and environment variables

## Testing

- Run contract tests: `pnpm run test:contracts`
- Run integration tests: `pnpm run test:core` (requires Docker)
- Run frontend tests: `pnpm --filter @tokentimer/dashboard test`

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce for bugs
- Check existing issues before opening a new one

## Security Issues

Please do **not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the same [AGPLv3 license](LICENSE) that covers the project. To keep the option of commercial dual-licensing (AGPLv3 + a separate commercial license) open, we may ask contributors to sign a contributor license agreement (CLA) granting Tokentimer Sàrl the rights needed to offer that commercial license.
