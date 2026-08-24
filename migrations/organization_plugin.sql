CREATE TABLE IF NOT EXISTS lucid_auth_organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    logo TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS lucid_auth_organization_members (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES lucid_auth_organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS lucid_auth_organization_members_user_idx
    ON lucid_auth_organization_members(user_id);

CREATE TABLE IF NOT EXISTS lucid_auth_organization_teams (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    organization_id UUID NOT NULL REFERENCES lucid_auth_organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ,
    UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS lucid_auth_organization_team_members (
    id UUID PRIMARY KEY,
    team_id UUID NOT NULL REFERENCES lucid_auth_organization_teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS lucid_auth_organization_invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES lucid_auth_organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    team_id TEXT,
    inviter_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS lucid_auth_organization_invitations_email_idx
    ON lucid_auth_organization_invitations(lower(email));

CREATE TABLE IF NOT EXISTS lucid_auth_organization_roles (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES lucid_auth_organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    permission JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ,
    UNIQUE (organization_id, role)
);
