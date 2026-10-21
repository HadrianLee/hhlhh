BEGIN;

CREATE TABLE IF NOT EXISTS identity.auth_challenges (
    challenge_id UUID NOT NULL,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    challenge BYTEA,
    otp_digest VARCHAR(64),
    rp_id VARCHAR(253),
    origin VARCHAR(2048),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attempts_remaining INTEGER DEFAULT 5 NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,
    cancelled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_auth_challenges PRIMARY KEY (challenge_id),
    CONSTRAINT ck_auth_challenges_purpose_allowed CHECK (
        purpose IN ('passkey_registration', 'passkey_authentication', 'email_otp')
    ),
    CONSTRAINT ck_auth_challenges_attempts_allowed CHECK (attempts_remaining BETWEEN 0 AND 5),
    CONSTRAINT ck_auth_challenges_purpose_data_valid CHECK (
        (purpose = 'email_otp' AND otp_digest IS NOT NULL AND length(otp_digest) = 64
         AND challenge IS NULL AND rp_id IS NULL AND origin IS NULL)
        OR (purpose <> 'email_otp' AND otp_digest IS NULL AND challenge IS NOT NULL
            AND length(challenge) >= 16 AND rp_id IS NOT NULL AND origin IS NOT NULL)
    ),
    CONSTRAINT fk_auth_challenges_user_id_users FOREIGN KEY (user_id)
        REFERENCES identity.users (user_id) ON DELETE CASCADE,
    CONSTRAINT fk_auth_challenges_session_id_user_sessions FOREIGN KEY (session_id)
        REFERENCES user_sessions (session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS identity.passkeys (
    credential_id BYTEA NOT NULL,
    user_id UUID NOT NULL,
    public_key BYTEA NOT NULL,
    rp_id VARCHAR(253) NOT NULL,
    sign_count BIGINT NOT NULL,
    device_type VARCHAR(20) NOT NULL,
    backed_up BOOLEAN NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_passkeys PRIMARY KEY (credential_id),
    CONSTRAINT ck_passkeys_credential_id_length CHECK (length(credential_id) BETWEEN 1 AND 1023),
    CONSTRAINT ck_passkeys_public_key_present CHECK (length(public_key) > 0),
    CONSTRAINT ck_passkeys_sign_count_allowed CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT ck_passkeys_device_type_allowed CHECK (device_type IN ('single_device', 'multi_device')),
    CONSTRAINT fk_passkeys_user_id_users FOREIGN KEY (user_id)
        REFERENCES identity.users (user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_auth_challenges_user_purpose_created
    ON identity.auth_challenges (user_id, purpose, created_at);
CREATE INDEX IF NOT EXISTS ix_auth_challenges_session_verified
    ON identity.auth_challenges (session_id, verified_at);
CREATE INDEX IF NOT EXISTS ix_passkeys_user_id ON identity.passkeys (user_id);

COMMIT;
