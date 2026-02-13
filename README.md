<h1 align="center">
  KMS
</h1>
<p align="center">
  <p align="center"><b>Open-source Key Management Service</b>: Manage secrets, API keys, certificates, and encryption keys across your infrastructure.</p>
</p>

<h4 align="center">
  <a href="https://hanzo.ai/discord">Discord</a> |
  <a href="https://kms.hanzo.ai">KMS Cloud</a> |
  <a href="https://kms.hanzo.ai/docs/self-hosting/overview">Self-Hosting</a> |
  <a href="https://kms.hanzo.ai/docs">Docs</a> |
  <a href="https://hanzo.ai">Hanzo AI</a>
</h4>

<h4 align="center">
  <a href="https://github.com/hanzoai/kms/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="KMS is released under the MIT license." />
  </a>
  <a href="https://github.com/hanzoai/kms/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs welcome!" />
  </a>
  <a href="https://github.com/hanzoai/kms/issues">
    <img src="https://img.shields.io/github/commit-activity/m/hanzoai/kms" alt="git commit activity" />
  </a>
</h4>

> **Note**: KMS is a fork of [Infisical](https://github.com/Infisical/infisical), the excellent open-source secret management platform. We extend our gratitude to the Infisical team for their foundational work.

## Introduction

**KMS** is the open-source key management service that teams use to centralize their application configuration, secrets (API keys, database credentials), and manage their internal PKI.

Built by [Hanzo AI](https://hanzo.ai), we're focused on making security tooling accessible to everyone, with a redesigned developer experience from the ground up.

## Features

### Secrets Management

- **Dashboard**: Manage secrets across projects and environments through a user-friendly interface.
- **Secret Syncs**: Sync secrets to platforms like GitHub, Vercel, AWS, and use tools like Terraform, Ansible, and more.
- **Secret versioning** and **Point-in-Time Recovery**: Track every secret and project state; roll back when needed.
- **Secret Rotation**: Rotate secrets at regular intervals for services like PostgreSQL, MySQL, AWS IAM, and more.
- **Dynamic Secrets**: Generate ephemeral secrets on-demand for services like PostgreSQL, MySQL, RabbitMQ, and more.
- **Secret Scanning and Leak Prevention**: Prevent secrets from leaking to git.
- **Kubernetes Operator**: Deliver secrets to your Kubernetes workloads and automatically reload deployments.
- **KMS Agent**: Inject secrets into applications without modifying any code logic.

### Certificate Management

- **Internal CA**: Create and manage a private CA hierarchy directly within KMS.
- **External CA**: Integrate with third-party certificate authorities such as Let's Encrypt, DigiCert, Microsoft AD CS, and more.
- **Certificate Lifecycle Management**: Create certificate profiles and policies to control how certificates are issued.
- **Certificate Syncs**: Sync certificates to external platforms like AWS Certificate Manager and Azure Key Vault.
- **Alerting**: Configure alerting for expiring CA and end-entity certificates.

### Key Management System (KMS)

- **Cryptographic Keys**: Centrally manage keys across projects through a user-friendly interface or via the API.
- **Encrypt and Decrypt Data**: Use symmetric keys to encrypt and decrypt data.

### SSH Management

- **Signed SSH Certificates**: Issue ephemeral SSH credentials for secure, short-lived, and centralized access to infrastructure.

### General Platform

- **Authentication Methods**: Authenticate machine identities with KMS using cloud-native or platform agnostic authentication methods (Kubernetes Auth, GCP Auth, Azure Auth, AWS Auth, OIDC Auth, Universal Auth).
- **Access Controls**: Define advanced authorization controls for users and machine identities with RBAC, additional privileges, temporary access, access requests, approval workflows, and more.
- **Audit logs**: Track every action taken on the platform.
- **Self-hosting**: Deploy KMS on-prem or cloud with ease; keep data on your own infrastructure.
- **SDKs**: Interact with KMS via client SDKs (Node, Python, Go, Ruby, Java, .NET)
- **CLI**: Interact with KMS via CLI; useful for injecting secrets into local development and CI/CD pipelines.
- **API**: Interact with KMS via REST API.

## Getting Started

### Run KMS locally

To set up and run KMS locally, make sure you have Git and Docker installed on your system. Then run:

**Linux/macOS:**
```console
git clone https://github.com/hanzoai/kms && cd kms && cp .env.dev.example .env && docker compose -f docker-compose.prod.yml up
```

**Windows Command Prompt:**
```console
git clone https://github.com/hanzoai/kms && cd kms && copy .env.dev.example .env && docker compose -f docker-compose.prod.yml up
```

Create an account at `http://localhost:80`

### Scan and prevent secret leaks

Scan for over 140+ secret types in your files, directories, and git repositories.

To scan your full git history, run:
```
hanzo-kms scan --verbose
```

Install pre-commit hook to scan each commit before you push:
```
hanzo-kms scan install --pre-commit-hook
```

## Open-source vs. paid

This repo is available under the [MIT expat license](https://github.com/hanzoai/kms/blob/main/LICENSE), with the exception of the `ee` directory which contains premium enterprise features requiring a license.

If you are interested in managed KMS Cloud or self-hosted Enterprise offering, visit [kms.hanzo.ai](https://kms.hanzo.ai) or [contact us](https://hanzo.ai/contact).

## Security

Please do not file GitHub issues or post on public forums for security vulnerabilities, as they are public!

KMS takes security issues very seriously. If you have any concerns or believe you have uncovered a vulnerability, please get in touch via email at security@hanzo.ai. In the message, try to provide a description of the issue and ideally a way of reproducing it. The security team will get back to you as soon as possible.

## Contributing

Whether it's big or small, we love contributions. Check out our guide to see how to [get started](https://kms.hanzo.ai/docs/contributing/getting-started).

Not sure where to get started? Join our [Discord](https://hanzo.ai/discord) and ask us any questions there.

## Acknowledgments

KMS is built on top of [Infisical](https://github.com/Infisical/infisical). We thank the Infisical team and community for creating an excellent foundation for secret management.
