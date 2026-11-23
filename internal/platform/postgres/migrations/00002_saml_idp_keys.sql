-- +goose Up
-- SAML IdP signing key and self-signed certificate per tenant (published in
-- the IdP metadata).
CREATE TABLE saml_idp_keys (
    tenant_id             uuid PRIMARY KEY REFERENCES tenants (id),
    certificate_der       bytea NOT NULL,
    private_key_encrypted bytea NOT NULL,
    encryption_key_id     text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE saml_idp_keys;
