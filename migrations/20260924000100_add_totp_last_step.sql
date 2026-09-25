-- RFC 6238 time step (unix seconds / 30) of the last TOTP code accepted for
-- this user. A code is accepted only for a newer step, so an observed code
-- cannot be replayed inside its validity window (RFC 6238 §5.2). NULL means
-- no code has been accepted since the secret was (re)issued.
ALTER TABLE user_mfa ADD COLUMN totp_last_step INTEGER;
