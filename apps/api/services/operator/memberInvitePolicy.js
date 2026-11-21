"use strict";
function registrationUrl(base, email, token) {
  return `${base}/register?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
}
async function lookupInviteEmailAccounts(client, email) {
  const { rows } = await client.query(
    "SELECT id,auth_method,email_verified FROM users WHERE LOWER(email)=$1 ORDER BY id LIMIT 2",
    [email],
  );
  return rows;
}

// SSO recipients prove the invited address on a subsequent sign-in.
function canAddExistingUserByEmail(user) {
  return user?.auth_method === "local" && user.email_verified === true;
}

module.exports = { registrationUrl, lookupInviteEmailAccounts, canAddExistingUserByEmail };
