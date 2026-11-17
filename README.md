# auth-api

The identity provider for ClusterKeep. It holds every account, checks passwords, keeps track of who is signed in and decides what each person can access. It replaced Authentik, so ClusterKeep doesn't depend on a third party for logins.

## What it does

- Stores accounts in Postgres. Passwords are hashed with Argon2id after an HMAC-SHA-512 pepper.
- Keeps sessions, login codes, refresh tokens and failed-login counts in Redis. Losing Redis signs everyone out but loses no accounts.
- Gives clusterkeep-ui an internal sessions API for logging in, changing passwords and logging out. auth-api serves no login pages of its own.
- Locks an account for 15 minutes after 10 failed logins, and takes the same time to answer for an unknown username as a wrong password.
- Acts as an OpenID Connect provider for Headlamp, so the Kubernetes API trusts its logins, and for Cloudflare Access in front of admin-ui. id tokens are signed with RS256 because that's what the Kubernetes API supports, and carry an ML-DSA-65 co-signature as well.
- Issues ML-DSA-65 service tokens that the other services use to call its admin API.
- Uses groups for access. `admin` runs admin-ui, and `cluster-admins`, `cluster-editors` and `cluster-viewers` give cluster access. Only cluster admins can hand out cluster groups.
- Creates a bootstrap `admin` account on first start, which has to change its password at first login.
- Returns the shared 404 page to browsers and JSON errors to API clients.

## Endpoints

### Health

| Method | Path | What it does |
|---|---|---|
| GET | `/healthz` | Kubernetes health check |
| GET | `/readyz` | Kubernetes readiness check, passes when Postgres and Redis are reachable |

### Sessions, for clusterkeep-ui

These need the registration token.

| Method | Path | What it does |
|---|---|---|
| POST | `/api/v1/register` | Create an account from clusterkeep-ui's join page |
| POST | `/api/v1/sessions` | Log in. Returns a session, or a change token if the password must be changed |
| POST | `/api/v1/sessions/password-change` | Set a new password with a change token and get a session |
| POST | `/api/v1/sessions/revoke` | End a session |

### Browser and OpenID Connect

| Method | Path | What it does |
|---|---|---|
| GET | `/login` | Sends the browser to the clusterkeep-ui login page |
| GET, POST | `/logout` | Ends the session in the cookie |
| GET | `/session` | Who the `ck_sso` cookie belongs to. The other services use this to check every request |
| GET | `/.well-known/openid-configuration` | OpenID Connect discovery |
| GET | `/jwks.json` | RS256 public keys |
| GET | `/pq/jwks.json` | ML-DSA-65 public key |
| GET | `/authorize` | Start an OpenID Connect login |
| POST | `/token` | Swap a login code or refresh token for tokens |
| GET | `/userinfo` | Profile of the user a bearer token belongs to |
| POST | `/introspect` | Check whether a token is still valid |

### Service tokens

| Method | Path | What it does |
|---|---|---|
| POST | `/api/v1/service-tokens` | Mint a service token for the signed-in user, using their session cookie |
| GET | `/api/v1/service-tokens/verify` | Check a service token passed as a bearer token |
| DELETE | `/api/v1/service-tokens/{credential_id}` | Revoke one of the signed-in user's service tokens |

### Accounts

These need a service token from someone in the `admin` or `cluster-admins` group.

| Method | Path | What it does |
|---|---|---|
| GET | `/api/v1/users` | List accounts |
| POST | `/api/v1/users` | Create an account |
| PATCH | `/api/v1/users/{user_id}/groups` | Change someone's groups |
| POST | `/api/v1/users/{user_id}/password` | Reset someone's password. They must change it at their next login |
| DELETE | `/api/v1/users/{user_id}/sessions` | Sign someone out everywhere |

The interactive API docs are at `/docs` everywhere except production.

## Technologies

- Python 3.13 and FastAPI, served by gunicorn with Uvicorn workers
- SQLAlchemy with asyncpg and Postgres for accounts, clients and signing keys
- Redis for sessions and other short-lived state
- argon2-cffi for password hashing
- pqcrypto for ML-DSA-65 signatures, PyJWT and cryptography for RS256 tokens
- pydantic-settings for configuration
- pytest with httpx and SQLite for the tests
- uv for dependencies, Docker for the image, Helm and OpenTofu for deployment

## Configuration

Every setting comes from an environment variable starting with `AUTH_API_`. The main ones are listed below.

| Variable | What it's for |
|---|---|
| `AUTH_API_DATABASE_URL` | Postgres connection |
| `AUTH_API_REDIS_URL` | Redis connection |
| `AUTH_API_ISSUER_URL` | Public address used as the token issuer |
| `AUTH_API_COOKIE_DOMAIN` | Domain for the `ck_sso` cookie, so every site shares it |
| `AUTH_API_PASSWORD_PEPPER` | Secret mixed into every password hash |
| `AUTH_API_REGISTRATION_TOKEN` | Token clusterkeep-ui uses for the sessions and register APIs |
| `AUTH_API_LOGIN_PAGE_URL` | The clusterkeep-ui login page |
| `AUTH_API_DEFAULT_REDIRECT_URL` | Where people go after logging in without a destination |
| `AUTH_API_HEADLAMP_URL` | Headlamp's address, for its OpenID Connect client |
| `AUTH_API_BOOTSTRAP_USERNAME` and `AUTH_API_BOOTSTRAP_PASSWORD` | The admin account created on first start |

## Running locally

The easiest way is [common-dev-env](https://github.com/LandRegistry/common-dev-env) with the [dev-env-config](https://github.com/ha-private-cloud/dev-env-config) repository, set up as the [organisation README](https://github.com/ha-private-cloud/.github/blob/main/profile/README.md#running-it-locally) describes. That runs it on http://localhost:9082 with its own Redis. The commands below run the tests.

```sh
uv sync
uv run pytest
```

There is also a small admin command.

```sh
uv run python -m app.manage list-users
echo 'new-password' | uv run python -m app.manage set-password <username>
```

## Deployment

The GitHub workflows come from the shared `pipelines` repo.

- Pushes to `development` and `preview` deploy to dev and preview.
- Pushing a `vX.Y.Z` tag builds the release image, and running the release workflow with that tag deploys it to production.

Each environment runs in its own namespace with its own Postgres and Redis. Production is reached through the Cloudflare Tunnel. The Helm chart is in `charts/auth-api` and the OpenTofu config is in `tofu/`.
