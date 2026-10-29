-- name: CreateUser :exec
INSERT INTO authn_users (id, public_id, realm_id, status, valid_from, valid_until, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetUser :one
SELECT * FROM authn_users WHERE realm_id = ? AND id = ?;

-- name: GetUserByPublicID :one
SELECT * FROM authn_users WHERE realm_id = ? AND public_id = ?;

-- name: ListUsers :many
SELECT * FROM authn_users WHERE realm_id = ? AND id > sqlc.arg(after) ORDER BY id LIMIT sqlc.arg(lim);

-- name: CreateEmail :exec
INSERT INTO authn_user_emails (id, public_id, realm_id, user_id, ciphertext, email_index, domain_index, index_key_id, verified_at, verified_via, is_primary, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetEmailByIndex :one
SELECT * FROM authn_user_emails WHERE realm_id = ? AND email_index = ?;

-- name: GetEmailByPublicID :one
SELECT * FROM authn_user_emails WHERE realm_id = ? AND public_id = ?;

-- name: GetEmail :one
SELECT * FROM authn_user_emails WHERE realm_id = ? AND id = ?;

-- name: SetPrimaryEmail :exec
UPDATE authn_user_emails SET is_primary = CASE WHEN id = sqlc.arg(id) THEN 1 ELSE 0 END WHERE realm_id = sqlc.arg(realm_id) AND user_id = sqlc.arg(user_id);

-- name: DeleteEmail :execrows
DELETE FROM authn_user_emails WHERE realm_id = ? AND id = ?;

-- name: ListEmailsByUser :many
SELECT * FROM authn_user_emails WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: CreateIdentity :exec
INSERT INTO authn_user_identities (id, public_id, realm_id, user_id, connection_id, provider_subject, created_at, revoked_at, revoke_reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetIdentityBySubject :one
SELECT * FROM authn_user_identities WHERE realm_id = ? AND connection_id = ? AND provider_subject = ? AND revoked_at IS NULL;

-- name: GetIdentityByPublicID :one
SELECT * FROM authn_user_identities WHERE realm_id = ? AND public_id = ?;

-- name: GetIdentity :one
SELECT * FROM authn_user_identities WHERE realm_id = ? AND id = ?;

-- name: RevokeIdentity :exec
UPDATE authn_user_identities SET revoked_at = ?, revoke_reason = ? WHERE realm_id = ? AND id = ? AND revoked_at IS NULL;

-- name: ListIdentitiesByUser :many
SELECT * FROM authn_user_identities WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: CreateConnection :exec
INSERT INTO authn_connections (id, realm_id, slug, type, config, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetConnection :one
SELECT * FROM authn_connections WHERE realm_id = ? AND id = ?;

-- name: GetConnectionBySlug :one
SELECT * FROM authn_connections WHERE realm_id = ? AND slug = ?;

-- name: ListConnections :many
SELECT * FROM authn_connections WHERE realm_id = ? ORDER BY slug;

-- name: CreateSession :exec
INSERT INTO authn_sessions (id, realm_id, principal_type, principal_id, active_org_id, token_hash, auth_methods, auth_credential_ids,
    warnings, ip, user_agent, authenticated_at, created_at, last_seen_at, expires_at, revoked_at, revoke_reason, restriction, sid)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT * FROM authn_sessions WHERE realm_id = ? AND id = ?;

-- name: GetCurrentSessionBySID :one
SELECT * FROM authn_sessions WHERE realm_id = ? AND sid = ? ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: ListSessionsByPrincipal :many
SELECT * FROM authn_sessions WHERE realm_id = ? AND principal_type = ? AND principal_id = ? ORDER BY created_at DESC, id DESC;

-- name: TouchSession :execrows
UPDATE authn_sessions SET last_seen_at = max(last_seen_at, sqlc.arg(at)) WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: RevokeSession :execrows
UPDATE authn_sessions SET
    revoke_reason = CASE WHEN revoked_at IS NULL OR revoked_at > sqlc.arg(at) THEN sqlc.arg(reason) ELSE revoke_reason END,
    revoked_at = CASE WHEN revoked_at IS NULL OR revoked_at > sqlc.arg(at) THEN sqlc.arg(at) ELSE revoked_at END
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: RevokeSessionsByPrincipal :many
UPDATE authn_sessions SET revoked_at = sqlc.arg(at), revoke_reason = sqlc.arg(reason)
WHERE realm_id = sqlc.arg(realm_id) AND principal_type = sqlc.arg(principal_type) AND principal_id = sqlc.arg(principal_id)
    AND id <> sqlc.arg(except_id) AND (revoked_at IS NULL OR revoked_at > sqlc.arg(at))
RETURNING id;

-- name: MoveSessionsOrg :many
UPDATE authn_sessions SET active_org_id = sqlc.arg(to_org_id)
WHERE realm_id = sqlc.arg(realm_id) AND principal_type = 'user' AND principal_id = sqlc.arg(user_id) AND active_org_id = sqlc.arg(from_org_id)
RETURNING id;

-- name: CreateServiceAccount :exec
INSERT INTO authn_service_accounts (id, realm_id, name, created_at) VALUES (?, ?, ?, ?);

-- name: GetServiceAccount :one
SELECT * FROM authn_service_accounts WHERE realm_id = ? AND id = ?;

-- name: CreateServiceAccountCredential :exec
INSERT INTO authn_service_account_credentials (id, realm_id, service_account_id, type, secret_hash, created_at, expires_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetServiceAccountCredential :one
SELECT * FROM authn_service_account_credentials WHERE realm_id = ? AND id = ?;

-- name: RevokeServiceAccountCredential :execrows
UPDATE authn_service_account_credentials SET revoked_at = coalesce(revoked_at, sqlc.arg(at)) WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: CreatePasskey :exec
INSERT INTO authn_passkeys (id, public_id, realm_id, user_id, credential_id, public_key, alg, sign_count, flags, aaguid,
    transports, name, created_at, last_used_at, revoked_at, revoke_reason, preferred_org_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: IsPasskeyCredentialRevoked :one
SELECT COUNT(*) FROM authn_revoked_passkey_credentials WHERE realm_id = ? AND credential_id = ?;

-- name: GetPasskeyByCredentialID :one
SELECT * FROM authn_passkeys WHERE realm_id = ? AND credential_id = ? AND revoked_at IS NULL;

-- name: GetPasskeyByPublicID :one
SELECT * FROM authn_passkeys WHERE realm_id = ? AND public_id = ?;

-- name: GetPasskey :one
SELECT * FROM authn_passkeys WHERE realm_id = ? AND id = ?;

-- name: ListPasskeysByUser :many
SELECT * FROM authn_passkeys WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: UsePasskey :execrows
UPDATE authn_passkeys SET sign_count = ?, flags = ?, last_used_at = ? WHERE realm_id = ? AND id = ?;

-- name: RenamePasskey :execrows
UPDATE authn_passkeys SET name = ? WHERE realm_id = ? AND id = ?;

-- name: SetPasskeyPreferredOrg :execrows
UPDATE authn_passkeys SET preferred_org_id = ? WHERE realm_id = ? AND id = ?;

-- name: RevokePasskey :exec
UPDATE authn_passkeys SET revoked_at = ?, revoke_reason = ? WHERE realm_id = ? AND id = ? AND revoked_at IS NULL;

-- name: AddRevokedPasskeyCredential :exec
INSERT INTO authn_revoked_passkey_credentials (realm_id, credential_id, revoked_at) VALUES (?, ?, ?)
ON CONFLICT (realm_id, credential_id) DO NOTHING;

-- name: CreateTOTP :exec
INSERT INTO authn_totp_credentials (id, public_id, realm_id, user_id, secret_ciphertext, last_used_step, created_at, revoked_at, revoke_reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetTOTPByPublicID :one
SELECT * FROM authn_totp_credentials WHERE realm_id = ? AND public_id = ?;

-- name: GetTOTP :one
SELECT * FROM authn_totp_credentials WHERE realm_id = ? AND id = ?;

-- name: ListTOTPByUser :many
SELECT * FROM authn_totp_credentials WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: UseTOTP :execrows
UPDATE authn_totp_credentials SET last_used_step = sqlc.arg(step)
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id) AND last_used_step < sqlc.arg(step);

-- name: RevokeTOTP :exec
UPDATE authn_totp_credentials SET revoked_at = ?, revoke_reason = ? WHERE realm_id = ? AND id = ? AND revoked_at IS NULL;

-- name: CreatePassword :exec
INSERT INTO authn_password_credentials (id, realm_id, user_id, hash, created_at, revoked_at, revoke_reason)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetPassword :one
SELECT * FROM authn_password_credentials WHERE realm_id = ? AND id = ?;

-- name: GetActivePassword :one
SELECT * FROM authn_password_credentials WHERE realm_id = ? AND user_id = ? AND revoked_at IS NULL;

-- name: UpdatePasswordHash :execrows
UPDATE authn_password_credentials SET hash = ? WHERE realm_id = ? AND id = ? AND revoked_at IS NULL;

-- name: RevokePassword :exec
UPDATE authn_password_credentials SET revoked_at = ?, revoke_reason = ? WHERE realm_id = ? AND id = ? AND revoked_at IS NULL;

-- name: SetUserValidity :execrows
UPDATE authn_users SET valid_from = ?, valid_until = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: SetUserDeletion :execrows
UPDATE authn_users SET deletion_scheduled_at = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: SetUserLegalHold :execrows
UPDATE authn_users SET legal_hold = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: MarkUserDeleted :execrows
UPDATE authn_users SET status = 'deleted', deletion_scheduled_at = NULL, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: EraseUserEmails :exec
DELETE FROM authn_user_emails WHERE realm_id = ? AND user_id = ?;

-- name: EraseUserIdentities :exec
DELETE FROM authn_user_identities WHERE realm_id = ? AND user_id = ?;

-- name: EraseUserPasskeys :exec
DELETE FROM authn_passkeys WHERE realm_id = ? AND user_id = ?;

-- name: EraseUserTOTP :exec
DELETE FROM authn_totp_credentials WHERE realm_id = ? AND user_id = ?;

-- name: EraseUserPasswords :exec
DELETE FROM authn_password_credentials WHERE realm_id = ? AND user_id = ?;

-- name: EraseUserRecoveryCodes :exec
DELETE FROM authn_recovery_codes WHERE realm_id = ? AND user_id = ?;

-- name: EraseUserSessions :exec
DELETE FROM authn_sessions WHERE realm_id = ? AND principal_type = 'user' AND principal_id = ?;

-- name: EraseUserRoleBindings :exec
DELETE FROM authz_role_bindings WHERE realm_id = ? AND principal_type = 'user' AND principal_id = ?;

-- name: EraseUserGroupMembers :exec
DELETE FROM authz_group_members WHERE member_type = 'user' AND member_id = sqlc.arg(user_id)
    AND group_id IN (SELECT id FROM authz_groups WHERE realm_id = sqlc.arg(realm_id));

-- name: CreateSuspension :exec
INSERT INTO authn_suspensions (id, public_id, realm_id, target_type, target_id, category, reason, external_ref, starts_at, ends_at,
    created_by, created_at, lifted_at, lifted_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSuspensionByPublicID :one
SELECT * FROM authn_suspensions WHERE realm_id = ? AND public_id = ?;

-- name: GetSuspension :one
SELECT * FROM authn_suspensions WHERE realm_id = ? AND id = ?;

-- name: ListSuspensionsByTarget :many
SELECT * FROM authn_suspensions WHERE realm_id = ? AND target_type = ? AND target_id = ? ORDER BY starts_at, id;

-- name: LiftSuspension :exec
UPDATE authn_suspensions SET lifted_at = ?, lifted_by = ? WHERE realm_id = ? AND id = ? AND lifted_at IS NULL;

-- name: ScheduleEvent :exec
INSERT INTO scheduled_events (id, realm_id, ref, event_type, payload, fire_at, fired_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DueScheduledEvents :many
SELECT * FROM scheduled_events WHERE fired_at IS NULL AND fire_at <= sqlc.arg(now) ORDER BY fire_at, id LIMIT sqlc.arg(lim);

-- name: MarkScheduledEventFired :execrows
UPDATE scheduled_events SET fired_at = ? WHERE realm_id = ? AND id = ? AND fired_at IS NULL;

-- name: CancelScheduledEvents :exec
DELETE FROM scheduled_events WHERE realm_id = ? AND ref = ? AND fired_at IS NULL;

-- name: DeleteRecoveryCodes :exec
DELETE FROM authn_recovery_codes WHERE realm_id = ? AND user_id = ?;

-- name: CreateRecoveryCode :exec
INSERT INTO authn_recovery_codes (id, realm_id, user_id, lookup, hash, created_at, used_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListRecoveryCodes :many
SELECT * FROM authn_recovery_codes WHERE realm_id = ? AND user_id = ? ORDER BY id;

-- name: UseRecoveryCode :execrows
UPDATE authn_recovery_codes SET used_at = ? WHERE realm_id = ? AND id = ? AND used_at IS NULL;

-- name: ClearEmailCiphertexts :execrows
UPDATE authn_user_emails SET ciphertext = sqlc.arg(empty) WHERE id IN (
    SELECT e.id FROM authn_user_emails e WHERE e.realm_id = sqlc.arg(realm_id) AND length(e.ciphertext) > 0 LIMIT sqlc.arg(lim));

-- name: DeleteEndedSessions :execrows
DELETE FROM authn_sessions WHERE id IN (
    SELECT s.id FROM authn_sessions s WHERE s.expires_at < sqlc.arg(before) OR s.revoked_at < sqlc.arg(before) LIMIT sqlc.arg(lim));

-- name: DeleteFiredScheduledEvents :execrows
DELETE FROM scheduled_events WHERE id IN (
    SELECT e.id FROM scheduled_events e WHERE e.fired_at IS NOT NULL AND e.fired_at < sqlc.arg(before) LIMIT sqlc.arg(lim));

-- name: CountPasswords :one
SELECT count(*) FROM authn_password_credentials;

-- name: PurgePasswords :execrows
DELETE FROM authn_password_credentials WHERE id IN (SELECT p.id FROM authn_password_credentials p LIMIT sqlc.arg(lim));
