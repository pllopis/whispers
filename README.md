# Whispers

A tiny OIDC‑protected web service for creating and sharing time‑limited secrets via unique links.

Created for [SKA](https://skao.int)'s SRCNet. Themed inspired by SKAO colours.

- Authenticated via your organisation’s OIDC issuer
- Per‑secret expiration
- Allowed users and/or groups (from a configurable OIDC claim)
- Encrypted at rest (Fernet)
- SQLite by default (simple single‑pod), Postgres optional

## Quick start on kind (SQLite)

### 1. Prerequisites

- Docker, kind, kubectl, Helm
- An OIDC client registered at your IdP  
  Redirect URI: `http://localhost:8080/callback`  
  Scopes: `openid profile email groups`

### 2. Build the image

```bash
docker build . -t whispers:0.1.0
kind load docker-image whispers:0.1.0 -n whispers
```

### 3. Create namespace and Secret

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Generate a session secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Create the Secret:

```bash
kubectl create ns whispers
kubectl -n whispers create secret generic whispers-secrets \
  --from-literal=OIDC_CLIENT_SECRET='<client-secret>' \
  --from-literal=SESSION_SECRET='<session-secret>' \
  --from-literal=FERNET_KEY='<fernet-key>'
```

### 4. Helm install

Edit `helm/whispers/values.yaml` minimally:

```yaml
env:
  OIDC_ISSUER: "https://ska-iam.stfc.ac.uk/"
  OIDC_CLIENT_ID: "<client-id>"
  OIDC_REDIRECT_URI: "http://localhost:8080/callback"
  BASE_URL: "http://localhost:8080"
  GROUPS_CLAIM: "groups"
existingSecret: "whispers-secrets"
sqlite:
  enabled: true
```

Install:

```bash
helm upgrade -i whispers ./helm/whispers -n whispers
kubectl -n whispers port-forward svc/whispers 8080:80
```

Open: [http://localhost:8080](http://localhost:8080)

## Usage

1. Login with your IAM account.
2. Create a secret with title/content, expiration hours, allowed users/groups.
3. Share the generated URL (`http://localhost:8080/s/<token>`).

If both allowed lists are empty, any authenticated user may view until expiry.

## Environment variables

- `OIDC_ISSUER`
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`
- `OIDC_REDIRECT_URI`
- `OIDC_SCOPES` (default `openid profile email groups`)
- `GROUPS_CLAIM` (default `groups`)
- `SESSION_SECRET`
- `FERNET_KEY`
- `BASE_URL` (no trailing slash)
- `DATABASE_URL` (set only if not using SQLite)

