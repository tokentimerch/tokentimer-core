# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in TokenTimer, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: [support@tokentimer.ch](mailto:support@tokentimer.ch)

We will acknowledge your report within 48 hours and work with you to understand and address the issue before any public disclosure.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | Yes                |

## Security Best Practices

When deploying TokenTimer:

- Always set a strong, unique `SESSION_SECRET` environment variable
- Use strong database passwords (never rely on defaults)
- Enable TLS/HTTPS for all production deployments
- Keep dependencies up to date
- Review the [Configuration Guide](docs/CONFIGURATION.md) for security-related settings
