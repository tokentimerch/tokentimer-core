const { pool } = require("../database");
const { logger } = require("../../utils/logger.js");

// Helper function to convert numeric fields from strings to numbers
const convertNumericFields = (token) => {
  if (token.key_size !== null && token.key_size !== undefined) {
    token.key_size = parseInt(token.key_size);
  }
  if (token.cost !== null && token.cost !== undefined) {
    token.cost = parseFloat(token.cost);
  }

  // Convert section to array if it's a string or contains comma-separated strings
  if (token.section) {
    if (typeof token.section === "string") {
      token.section = token.section
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (Array.isArray(token.section)) {
      // If some elements in the array contain commas, split them too
      const flat = [];
      for (const part of token.section) {
        if (typeof part === "string" && part.includes(",")) {
          part
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
            .forEach((s) => flat.push(s));
        } else if (part) {
          flat.push(typeof part === "string" ? part.trim() : part);
        }
      }
      token.section = flat.length > 0 ? [...new Set(flat)] : null;
    }
  }

  // Convert expiration to expiresAt for frontend compatibility
  // If missing or null, default to "never expires" sentinel (2099-12-31)
  const date = token.expiration
    ? new Date(token.expiration)
    : new Date("2099-12-31");
  token.expiresAt = date.toISOString().split("T")[0];
  delete token.expiration;

  // Format renewal_date consistently as YYYY-MM-DD
  if (token.renewal_date) {
    const date = new Date(token.renewal_date);
    token.renewal_date = date.toISOString().split("T")[0];
  }

  // Ensure last_used, created_at, imported_at are ISO strings if they exist
  // (node-pg might return them as Date objects or strings)
  ["last_used", "created_at", "imported_at"].forEach((field) => {
    if (token[field] instanceof Date) {
      token[field] = token[field].toISOString();
    }
  });

  return token;
};

const findByUserId = async (userId) => {
  const query = `
    SELECT * FROM tokens 
    WHERE user_id = $1 
    ORDER BY created_at DESC
  `;
  const result = await pool.query(query, [userId]);

  // Convert numeric fields from strings to numbers for all tokens
  return result.rows.map((token) => convertNumericFields(token));
};

const findById = async (id) => {
  const query = "SELECT * FROM tokens WHERE id = $1";
  const result = await pool.query(query, [id]);
  const token = result.rows[0];

  // Convert numeric fields from strings to numbers
  return token ? convertNumericFields(token) : null;
};

const create = async (tokenData) => {
  const {
    userId,
    workspaceId = null,
    created_by = null,
    name,
    expiration,
    type,
    category = "general",
    domains,
    location,
    used_by,
    section = null,
    contact_group_id = null,
    issuer,
    serial_number,
    subject,
    key_size,
    algorithm,
    license_type,
    vendor,
    cost,
    renewal_url,
    renewal_date,
    contacts,
    description,
    notes,
    privileges = null,
    imported_at = null,
    last_used = null,
    created_at = null,
  } = tokenData;

  const query = `
    INSERT INTO tokens (
      user_id, workspace_id, created_by, name, expiration, type, category, domains, location, used_by, section, contact_group_id,
      issuer, serial_number, subject, key_size, algorithm, license_type, vendor, cost,
      renewal_url, renewal_date, contacts, description, notes, privileges, imported_at, last_used, created_at, updated_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, NOW())
    RETURNING *
  `;

  const values = [
    userId,
    workspaceId,
    created_by,
    name,
    expiration,
    type,
    category,
    domains,
    location,
    used_by,
    section,
    contact_group_id,
    issuer,
    serial_number,
    subject,
    key_size,
    algorithm,
    license_type,
    vendor,
    cost,
    renewal_url,
    renewal_date,
    contacts,
    description,
    notes,
    privileges,
    imported_at || null,
    last_used,
    created_at || null,
  ];

  try {
    const result = await pool.query(query, values);
    const token = result.rows[0];

    // Convert numeric fields from strings to numbers
    return convertNumericFields(token);
  } catch (error) {
    // Enhanced error logging for database operations
    logger.error("create() database error:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
      hint: error.hint,
      query,
      values: values.map((v, i) => `$${i + 1}: ${v}`),
    });

    // Re-throw the error for the API layer to handle
    throw error;
  }
};

const update = async (id, tokenData) => {
  const {
    name,
    expiration,
    type,
    category,
    domains,
    location,
    used_by,
    section,
    contact_group_id,
    issuer,
    serial_number,
    subject,
    key_size,
    algorithm,
    license_type,
    vendor,
    cost,
    renewal_url,
    renewal_date,
    contacts,
    description,
    notes,
    privileges,
    last_used,
    created_at,
    imported_at,
  } = tokenData;

  // Build dynamic query to only update provided fields
  const updateFields = [];
  const values = [id];
  let paramIndex = 2;

  if (name !== undefined) {
    updateFields.push(`name = $${paramIndex++}`);
    values.push(name);
  }
  if (expiration !== undefined) {
    updateFields.push(`expiration = $${paramIndex++}`);
    values.push(expiration);
  }
  if (type !== undefined) {
    updateFields.push(`type = $${paramIndex++}`);
    values.push(type);
  }
  if (category !== undefined) {
    updateFields.push(`category = $${paramIndex++}`);
    values.push(category);
  }
  if (domains !== undefined) {
    updateFields.push(`domains = $${paramIndex++}`);
    values.push(domains);
  }
  if (location !== undefined) {
    updateFields.push(`location = $${paramIndex++}`);
    values.push(location);
  }
  if (used_by !== undefined) {
    updateFields.push(`used_by = $${paramIndex++}`);
    values.push(used_by);
  }
  if (section !== undefined) {
    updateFields.push(`section = $${paramIndex++}`);
    values.push(section);
  }
  if (contact_group_id !== undefined) {
    updateFields.push(`contact_group_id = $${paramIndex++}`);
    values.push(contact_group_id);
  }
  if (issuer !== undefined) {
    updateFields.push(`issuer = $${paramIndex++}`);
    values.push(issuer);
  }
  if (serial_number !== undefined) {
    updateFields.push(`serial_number = $${paramIndex++}`);
    values.push(serial_number);
  }
  if (subject !== undefined) {
    updateFields.push(`subject = $${paramIndex++}`);
    values.push(subject);
  }
  if (key_size !== undefined) {
    updateFields.push(`key_size = $${paramIndex++}`);
    values.push(key_size);
  }
  if (algorithm !== undefined) {
    updateFields.push(`algorithm = $${paramIndex++}`);
    values.push(algorithm);
  }
  if (license_type !== undefined) {
    updateFields.push(`license_type = $${paramIndex++}`);
    values.push(license_type);
  }
  if (vendor !== undefined) {
    updateFields.push(`vendor = $${paramIndex++}`);
    values.push(vendor);
  }
  if (cost !== undefined) {
    updateFields.push(`cost = $${paramIndex++}`);
    values.push(cost);
  }
  if (renewal_url !== undefined) {
    updateFields.push(`renewal_url = $${paramIndex++}`);
    values.push(renewal_url);
  }
  if (renewal_date !== undefined) {
    updateFields.push(`renewal_date = $${paramIndex++}`);
    values.push(renewal_date);
  }
  if (contacts !== undefined) {
    updateFields.push(`contacts = $${paramIndex++}`);
    values.push(contacts);
  }
  if (description !== undefined) {
    updateFields.push(`description = $${paramIndex++}`);
    values.push(description);
  }
  if (notes !== undefined) {
    updateFields.push(`notes = $${paramIndex++}`);
    values.push(notes);
  }
  if (privileges !== undefined) {
    updateFields.push(`privileges = $${paramIndex++}`);
    values.push(privileges);
  }
  if (last_used !== undefined) {
    updateFields.push(`last_used = $${paramIndex++}`);
    values.push(last_used);
  }
  if (created_at !== undefined) {
    updateFields.push(`created_at = $${paramIndex++}`);
    values.push(created_at);
  }
  if (imported_at !== undefined) {
    updateFields.push(`imported_at = $${paramIndex++}`);
    values.push(imported_at);
  }

  // If no fields to update, return the existing token
  if (updateFields.length === 0) {
    const existingToken = await findById(id);
    return existingToken;
  }

  // Always update the updated_at timestamp
  updateFields.push("updated_at = NOW()");

  const query = `
    UPDATE tokens 
    SET ${updateFields.join(", ")}
    WHERE id = $1
    RETURNING *
  `;

  try {
    const result = await pool.query(query, values);
    const token = result.rows[0];

    if (!token) {
      throw new Error("Token not found or update failed");
    }

    // Convert numeric fields from strings to numbers
    return convertNumericFields(token);
  } catch (error) {
    // Enhanced error logging for database operations
    logger.error("update() database error:", {
      message: error.message,
      code: error.code,
      detail: error.detail,
      hint: error.hint,
      query,
      values: values.map((v, i) => `$${i + 1}: ${v}`),
    });

    // Re-throw the error for the API layer to handle
    throw error;
  }
};

const deleteById = async (id) => {
  const query = "DELETE FROM tokens WHERE id = $1 RETURNING *";
  const result = await pool.query(query, [id]);
  const token = result.rows[0];

  // Convert numeric fields from strings to numbers
  return token ? convertNumericFields(token) : null;
};

const deleteAllByUserId = async (userId) => {
  const query = "DELETE FROM tokens WHERE user_id = $1";
  const result = await pool.query(query, [userId]);
  return result.rowCount;
};

// Get tokens by category
const findByCategory = async (userId, category) => {
  const query = `
    SELECT * FROM tokens 
    WHERE user_id = $1 AND category = $2
    ORDER BY created_at DESC
  `;
  const result = await pool.query(query, [userId, category]);

  // Convert numeric fields from strings to numbers for all tokens
  return result.rows.map((token) => convertNumericFields(token));
};

// Get tokens expiring soon
const findExpiringSoon = async (userId, days = 30) => {
  const query = `
    SELECT * FROM tokens 
    WHERE user_id = $1 
      AND expiration <= NOW() + INTERVAL '${days} days'
      AND expiration > NOW()
    ORDER BY expiration ASC
  `;
  const result = await pool.query(query, [userId]);

  // Convert numeric fields from strings to numbers for all tokens
  return result.rows.map((token) => convertNumericFields(token));
};

// Get tokens by domain
const findByDomain = async (userId, domain) => {
  const query = `
    SELECT * FROM tokens 
    WHERE user_id = $1 
      AND domains @> ARRAY[$2]
    ORDER BY created_at DESC
  `;
  const result = await pool.query(query, [userId, domain]);

  // Convert numeric fields from strings to numbers for all tokens
  return result.rows.map((token) => convertNumericFields(token));
};

// Find token by name, location, and workspaceId (for deduplication during imports)
const findByNameLocationAndWorkspace = async (name, location, workspaceId) => {
  // Both name AND location are required for deduplication
  if (!name) return null;
  if (location === null || location === undefined || location === "")
    return null;

  const query = `
    SELECT * FROM tokens 
    WHERE name = $1 
      AND workspace_id = $2
      AND location = $3
    LIMIT 1
  `;
  const values = [name, workspaceId, location];

  const result = await pool.query(query, values);
  const token = result.rows[0];

  // Convert numeric fields from strings to numbers
  return token ? convertNumericFields(token) : null;
};

module.exports = {
  convertNumericFields,
  findByUserId,
  findById,
  create,
  update,
  delete: deleteById,
  deleteAllByUserId,
  findByCategory,
  findExpiringSoon,
  findByDomain,
  findByNameLocationAndWorkspace,
};
