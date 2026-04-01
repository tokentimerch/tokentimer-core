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
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/) format:
   ```
   feat(core-api): add new endpoint for X
   fix(core-ui): resolve rendering issue in Y
   ```
5. Open a Pull Request against `main`

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

By contributing, you agree that your contributions will be licensed under the same [BUSL-1.1 license](LICENSE) that covers the project.
