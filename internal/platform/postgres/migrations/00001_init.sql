-- +goose Up

-- Every tenant-owned table has tenant_id and references its parents with
-- (tenant_id, id) composite foreign keys, so cross-tenant references are
-- impossible at the database level.

CREATE TABLE tenants (
    id         uuid PRIMARY KEY,
    slug       text NOT NULL UNIQUE,
    name       text NOT NULL,
    settings   jsonb NOT NULL DEFAULT '{}',
    version    bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- identity
CREATE TABLE users (
    id                 uuid NOT NULL,
    tenant_id          uuid NOT NULL REFERENCES tenants (id),
    login_id           text NOT NULL,
    email              text NOT NULL,
    email_verified     boolean NOT NULL DEFAULT false,
    given_name         text NOT NULL DEFAULT '',
    family_name        text NOT NULL DEFAULT '',
    status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'locked')),
    failed_login_count int NOT NULL DEFAULT 0,
    locked_until       timestamptz,
    version            bigint NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    deleted_at         timestamptz,
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX users_login_id ON users (tenant_id, lower(login_id)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX users_email ON users (tenant_id, lower(email)) WHERE deleted_at IS NULL;

CREATE TABLE groups (
    id         uuid NOT NULL PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    name       text NOT NULL,
    version    bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE roles (
    id          uuid NOT NULL PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    version     bigint NOT NULL DEFAULT 1,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE group_members (
    tenant_id uuid NOT NULL,
    group_id  uuid NOT NULL,
    user_id   uuid NOT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE user_roles (
    tenant_id uuid NOT NULL,
    user_id   uuid NOT NULL,
    role_id   uuid NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE group_roles (
    tenant_id uuid NOT NULL,
    group_id  uuid NOT NULL,
    role_id   uuid NOT NULL,
    PRIMARY KEY (group_id, role_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------- authn
CREATE TABLE password_credentials (
    user_id       uuid NOT NULL PRIMARY KEY,
    tenant_id     uuid NOT NULL,
    password_hash text NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE totp_credentials (
    id                uuid NOT NULL PRIMARY KEY,
    tenant_id         uuid NOT NULL,
    user_id           uuid NOT NULL,
    secret_encrypted  bytea NOT NULL,
    encryption_key_id text NOT NULL,
    last_used_step    bigint NOT NULL DEFAULT 0,
    confirmed_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE recovery_codes (
    id         uuid NOT NULL PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    user_id    uuid NOT NULL,
    code_hash  text NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE webauthn_credentials (
    id            uuid NOT NULL PRIMARY KEY,
    tenant_id     uuid NOT NULL,
    user_id       uuid NOT NULL,
    credential_id bytea NOT NULL,
    credential    jsonb NOT NULL,
    label         text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    UNIQUE (tenant_id, credential_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE sessions (
    id              uuid NOT NULL PRIMARY KEY,
    tenant_id       uuid NOT NULL,
    user_id         uuid NOT NULL,
    session_id_hash text NOT NULL UNIQUE,
    auth_time       timestamptz NOT NULL,
    acr             text NOT NULL,
    amr             text[] NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE one_time_tokens (
    token_hash  text NOT NULL PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    user_id     uuid NOT NULL,
    purpose     text NOT NULL CHECK (purpose IN ('password_reset', 'email_verification')),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------- oidc
CREATE TABLE clients (
    id                         uuid NOT NULL PRIMARY KEY,
    tenant_id                  uuid NOT NULL REFERENCES tenants (id),
    client_id                  text NOT NULL,
    name                       text NOT NULL,
    client_type                text NOT NULL CHECK (client_type IN ('confidential', 'public')),
    first_party                boolean NOT NULL DEFAULT false,
    token_endpoint_auth_method text NOT NULL CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none')),
    grant_types                text[] NOT NULL,
    redirect_uris              text[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris  text[] NOT NULL DEFAULT '{}',
    backchannel_logout_uri     text,
    allowed_scopes             text[] NOT NULL DEFAULT '{}',
    access_token_format        text NOT NULL DEFAULT 'jwt' CHECK (access_token_format IN ('jwt', 'opaque')),
    version                    bigint NOT NULL DEFAULT 1,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, client_id)
);

CREATE TABLE client_secrets (
    id          uuid NOT NULL PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    client_id   uuid NOT NULL,
    secret_hash text NOT NULL,
    expires_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE consents (
    tenant_id  uuid NOT NULL,
    user_id    uuid NOT NULL,
    client_id  uuid NOT NULL,
    scopes     text[] NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE authorization_codes (
    code_hash      text NOT NULL PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    grant_id       uuid NOT NULL,
    client_id      uuid NOT NULL,
    user_id        uuid NOT NULL,
    session_id     uuid NOT NULL,
    redirect_uri   text NOT NULL,
    scopes         text[] NOT NULL,
    nonce          text NOT NULL,
    code_challenge text NOT NULL,
    auth_time      timestamptz NOT NULL,
    acr            text NOT NULL,
    amr            text[] NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, session_id) REFERENCES sessions (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE refresh_tokens (
    id         uuid NOT NULL PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    grant_id   uuid NOT NULL,
    parent_id  uuid REFERENCES refresh_tokens (id) ON DELETE CASCADE,
    client_id  uuid NOT NULL,
    user_id    uuid NOT NULL,
    session_id uuid,
    scopes     text[] NOT NULL,
    auth_time  timestamptz NOT NULL,
    acr        text NOT NULL,
    amr        text[] NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX refresh_tokens_grant ON refresh_tokens (grant_id);

CREATE TABLE access_tokens (
    jti        text NOT NULL PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    token_hash text UNIQUE,
    grant_id   uuid,
    client_id  uuid NOT NULL,
    user_id    uuid,
    scopes     text[] NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX access_tokens_grant ON access_tokens (grant_id);

-- ---------------------------------------------------------------- federation
CREATE TABLE identity_providers (
    id                      uuid NOT NULL PRIMARY KEY,
    tenant_id               uuid NOT NULL REFERENCES tenants (id),
    name                    text NOT NULL,
    type                    text NOT NULL CHECK (type IN ('oidc')),
    issuer                  text NOT NULL,
    client_id               text NOT NULL,
    client_secret_encrypted bytea NOT NULL,
    encryption_key_id       text NOT NULL,
    scopes                  text[] NOT NULL,
    allow_signup            boolean NOT NULL DEFAULT false,
    version                 bigint NOT NULL DEFAULT 1,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE federated_identities (
    id          uuid NOT NULL PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    user_id     uuid NOT NULL,
    provider_id uuid NOT NULL,
    subject     text NOT NULL,
    email       text NOT NULL DEFAULT '',
    linked_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, subject),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, provider_id) REFERENCES identity_providers (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE saml_service_providers (
    id                  uuid NOT NULL PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenants (id),
    entity_id           text NOT NULL,
    metadata_xml        text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, entity_id)
);

-- ---------------------------------------------------------------- keys
CREATE TABLE signing_keys (
    kid                   text NOT NULL PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants (id),
    alg                   text NOT NULL,
    status                text NOT NULL CHECK (status IN ('next', 'current', 'retiring', 'retired')),
    public_jwk            jsonb NOT NULL,
    private_key_encrypted bytea NOT NULL,
    encryption_key_id     text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    activated_at          timestamptz,
    retiring_at           timestamptz,
    retired_at            timestamptz
);
CREATE UNIQUE INDEX signing_keys_one_current ON signing_keys (tenant_id) WHERE status = 'current';

-- ---------------------------------------------------------------- audit / webhooks
CREATE TABLE outbox_events (
    id             uuid NOT NULL PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    event_type     text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id   text NOT NULL,
    payload        jsonb NOT NULL,
    actor_type     text NOT NULL,
    actor_id       text,
    result         text NOT NULL DEFAULT 'success',
    ip             text NOT NULL DEFAULT '',
    user_agent     text NOT NULL DEFAULT '',
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    processed_at   timestamptz
);
CREATE INDEX outbox_events_unprocessed ON outbox_events (occurred_at) WHERE processed_at IS NULL;

CREATE TABLE audit_logs (
    seq         bigserial PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    event_id    uuid NOT NULL UNIQUE,
    occurred_at timestamptz NOT NULL,
    actor_type  text NOT NULL,
    actor_id    text,
    action      text NOT NULL,
    target_type text NOT NULL,
    target_id   text NOT NULL,
    result      text NOT NULL,
    ip          text NOT NULL,
    user_agent  text NOT NULL,
    details     jsonb NOT NULL,
    prev_hash   bytea NOT NULL,
    hash        bytea NOT NULL
);
CREATE INDEX audit_logs_tenant ON audit_logs (tenant_id, seq);

-- Audit logs are append-only.
-- +goose StatementBegin
CREATE FUNCTION audit_logs_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();

CREATE TABLE webhook_endpoints (
    id                uuid NOT NULL PRIMARY KEY,
    tenant_id         uuid NOT NULL REFERENCES tenants (id),
    url               text NOT NULL,
    secret_encrypted  bytea NOT NULL,
    encryption_key_id text NOT NULL,
    event_types       text[] NOT NULL,
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE webhook_deliveries (
    id               uuid NOT NULL PRIMARY KEY,
    tenant_id        uuid NOT NULL,
    endpoint_id      uuid NOT NULL,
    event_id         uuid NOT NULL REFERENCES outbox_events (id),
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed')),
    attempts         int NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_status_code int,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, event_id),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES webhook_endpoints (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at) WHERE status = 'pending';

-- +goose Down
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
