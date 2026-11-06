"use strict";
function registrationUrl(base, email, token) {
  return `${base}/register?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
}
module.exports = { registrationUrl };
