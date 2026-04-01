const { pool } = require("../database");

// Canonicalize emails to prevent duplicates across OAuth and local accounts.
const canonicalizeEmail = (email) => {
  const raw = String(email || "")
    .trim()
    .toLowerCase();
  if (!raw) return raw;
  const [local, domain] = raw.split("@");
  if (!domain) return raw;
  const isGmail = domain === "gmail.com" || domain === "googlemail.com";
  if (!isGmail) return `${local}@${domain}`;
  const plusIndex = local.indexOf("+");
  const withoutTag = plusIndex >= 0 ? local.slice(0, plusIndex) : local;
  const withoutDots = withoutTag.replace(/\./g, "");
  return `${withoutDots}@gmail.com`;
};

const findById = async (id) => {
  const query = "SELECT * FROM users WHERE id = $1";
  const result = await pool.query(query, [id]);
  return result.rows[0];
};

const update = async (id, userData) => {
  const {
    displayName,
    firstName,
    lastName,
    email,
    photo,
    accessToken,
    refreshToken,
    tokenExpiry,
  } = userData;

  const query = `
    UPDATE users 
    SET display_name = $2, first_name = $3, last_name = $4, email = $5, photo = $6, access_token = $7, 
        refresh_token = $8, token_expiry = $9, updated_at = NOW()
    WHERE id = $1
    RETURNING *
  `;

  const values = [
    id,
    displayName,
    firstName || null,
    lastName || null,
    email ? canonicalizeEmail(email) : null,
    photo,
    accessToken,
    refreshToken,
    tokenExpiry,
  ];
  const result = await pool.query(query, values);
  return result.rows[0];
};

const findByEmail = async (email) => {
  const normalizedEmail = canonicalizeEmail(email);
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [
    normalizedEmail,
  ]);
  return result.rows[0];
};

const findByEmailLoose = async (email) => {
  const raw = String(email || "").trim();
  if (!raw) return null;
  const result = await pool.query(
    "SELECT * FROM users WHERE LOWER(email) = LOWER($1)",
    [raw],
  );
  return result.rows[0];
};

const createLocal = async (userData) => {
  const {
    email,
    emailOriginal,
    displayName,
    firstName,
    lastName,
    passwordHash,
    authMethod,
    photo,
    verificationToken,
    verificationTokenExpires,
  } = userData;
  try {
    const result = await pool.query(
      `INSERT INTO users (email, email_original, display_name, first_name, last_name, password_hash, auth_method, photo, verification_token, verification_token_expires, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
       RETURNING *`,
      [
        canonicalizeEmail(email),
        emailOriginal,
        displayName,
        firstName || null,
        lastName || null,
        passwordHash,
        authMethod,
        photo,
        verificationToken,
        verificationTokenExpires,
      ],
    );
    return result.rows[0];
  } catch (error) {
    if (error.code === "23505" && error.constraint === "users_email_key") {
      throw new Error("An account with this email already exists");
    }
    throw error;
  }
};

const verifyEmail = async (token) => {
  const result = await pool.query(
    `UPDATE users 
     SET email_verified = TRUE, verification_token = NULL, verification_token_expires = NULL, updated_at = NOW()
     WHERE verification_token = $1 AND verification_token_expires > NOW()
     RETURNING *`,
    [token],
  );
  return result.rows[0];
};

const findByVerificationToken = async (token) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE verification_token = $1 AND verification_token_expires > NOW()",
    [token],
  );
  return result.rows[0];
};

const setVerificationToken = async (email, token, expires) => {
  const normalizedEmail = canonicalizeEmail(email);
  const result = await pool.query(
    `UPDATE users 
     SET verification_token = $2, verification_token_expires = $3, updated_at = NOW()
     WHERE email = $1
     RETURNING *`,
    [normalizedEmail, token, expires],
  );
  return result.rows[0];
};

const findByResetToken = async (token) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()",
    [token],
  );
  return result.rows[0];
};

const setResetToken = async (email, token, expires) => {
  const normalizedEmail = canonicalizeEmail(email);
  const result = await pool.query(
    `UPDATE users 
     SET reset_token = $2, reset_token_expires = $3, updated_at = NOW()
     WHERE email = $1
     RETURNING *`,
    [normalizedEmail, token, expires],
  );
  return result.rows[0];
};

const setResetTokenByUserId = async (userId, token, expires) => {
  const result = await pool.query(
    `UPDATE users 
     SET reset_token = $2, reset_token_expires = $3, updated_at = NOW()
     WHERE id = $1
     RETURNING *`,
    [userId, token, expires],
  );
  return result.rows[0];
};

const resetPassword = async (token, newPasswordHash) => {
  const result = await pool.query(
    `UPDATE users 
     SET password_hash = $2, reset_token = NULL, reset_token_expires = NULL, updated_at = NOW()
     WHERE reset_token = $1 AND reset_token_expires > NOW()
     RETURNING *`,
    [token, newPasswordHash],
  );
  return result.rows[0];
};

module.exports = {
  canonicalizeEmail,
  findById,
  update,
  findByEmail,
  findByEmailLoose,
  createLocal,
  verifyEmail,
  findByVerificationToken,
  setVerificationToken,
  findByResetToken,
  setResetToken,
  setResetTokenByUserId,
  resetPassword,
};
