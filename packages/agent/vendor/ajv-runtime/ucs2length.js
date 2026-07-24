/*
 * VENDORED COPY for self-contained agent distribution.
 * Source: ajv/dist/runtime/ucs2length.js (MIT License, ajv project).
 * Used only by the generated protocol validator's minLength/maxLength
 * checks. Refresh with: node packages/agent/scripts/build-protocol-validator.js
 */
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// https://mathiasbynens.be/notes/javascript-encoding
// https://github.com/bestiejs/punycode.js - punycode.ucs2.decode
function ucs2length(str) {
    const len = str.length;
    let length = 0;
    let pos = 0;
    let value;
    while (pos < len) {
        length++;
        value = str.charCodeAt(pos++);
        if (value >= 0xd800 && value <= 0xdbff && pos < len) {
            // high surrogate, and there is a next character
            value = str.charCodeAt(pos);
            if ((value & 0xfc00) === 0xdc00)
                pos++; // low surrogate
        }
    }
    return length;
}
exports.default = ucs2length;
//# sourceMappingURL=ucs2length.js.map