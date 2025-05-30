# Docker Hub Authentication for GitHub Actions

This guide explains how to set up Docker Hub authentication for the GitHub Actions workflows in this repository.

## Overview

The repository uses Docker Hub to publish container images through GitHub Actions. Authentication is required to push images to Docker Hub.

**Note**: This guide supplements the general Docker CI/CD documentation in [docker-ci-cd.md](./docker-ci-cd.md) with specific authentication setup instructions.

## Setup Instructions

### 1. Create a Docker Hub Access Token

1. Log in to [Docker Hub](https://hub.docker.com)
2. Navigate to [Account Settings → Security](https://hub.docker.com/settings/security)
3. Click "New Access Token"
4. Configure the token:
   - **Description**: Give it a meaningful name (e.g., "GitHub Actions - claude-github-webhook")
   - **Access permissions**: Select "Read & Write" to allow pushing images
5. Click "Generate"
6. **Important**: Copy the token immediately - it won't be shown again

### 2. Add the Token to GitHub

You can add the token as either a repository secret or an organization secret.

#### Option A: Repository Secret

1. Go to your GitHub repository
2. Navigate to Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Add the secret:
   - **Name**: `DOCKER_HUB_TOKEN`
   - **Value**: Paste your Docker Hub access token
5. Click "Add secret"

#### Option B: Organization Secret

1. Go to your GitHub organization settings
2. Navigate to Secrets and variables → Actions
3. Click "New organization secret" or edit an existing one
4. Add the secret:
   - **Name**: `DOCKER_HUB_TOKEN`
   - **Value**: Paste your Docker Hub access token
5. Configure repository access:
   - **All repositories**: Makes it available to all repos in the organization
   - **Private repositories**: Only private repos can access it
   - **Selected repositories**: Choose specific repos (ensure this repository is selected)
6. Save the secret

## Verification

The workflows that use Docker Hub authentication include:
- `.github/workflows/docker-publish.yml` - Contains two jobs that publish Docker images:
  - `build` job - Builds and publishes the main webhook service image
  - `build-claudecode` job - Builds and publishes the Claude Code container image

These workflows reference the token using:
```yaml
- name: Log in to Docker Hub
  uses: docker/login-action@v3
  with:
    username: ${{ env.DOCKER_HUB_USERNAME }}  # Hardcoded as 'cheffromspace' in workflow
    password: ${{ secrets.DOCKER_HUB_TOKEN }}  # Your secret token
```

**Important**: The username (`DOCKER_HUB_USERNAME`) is defined as an environment variable in the workflow file and is currently set to `cheffromspace`. Only the `DOCKER_HUB_TOKEN` needs to be configured as a secret.

## Troubleshooting

If you encounter authentication errors:

1. **Verify the secret name**: Ensure it's exactly `DOCKER_HUB_TOKEN` (case-sensitive)
2. **Check repository access**: If using an organization secret, verify the repository is included in the access list
3. **Token validity**: Ensure the Docker Hub token hasn't expired or been revoked
4. **Token permissions**: Verify the token has "Read & Write" permissions
5. **Username**: The `DOCKER_HUB_USERNAME` is hardcoded in the workflow as `cheffromspace`. If you need to use a different Docker Hub account, you'll need to modify the workflow file

## Security Best Practices

- Use access tokens instead of passwords
- Grant minimal required permissions (Read & Write for pushing images)
- Rotate tokens periodically
- Use organization secrets for multiple repositories to centralize management
- Never commit tokens or credentials to the repository