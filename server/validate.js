'use strict';

const crypto = require('node:crypto');

const USERNAME_REGEX = /^[a-z0-9](?:[a-z0-9._-]{1,28})[a-z0-9]$/;
const RANDOM_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

const RESERVED_USERNAMES = new Set([
  'admin',
  'administrator',
  'root',
  'postmaster',
  'abuse',
  'hostmaster',
  'webmaster',
  'support',
  'noreply',
  'no-reply',
  'security',
  'info',
  'mail',
]);

function normalizeUsername(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim().toLowerCase();
}

function normalizeAddress(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim().toLowerCase();
}

function validateUsername(rawUsername) {
  const username = normalizeUsername(rawUsername);
  if (!username) {
    return { valid: false, error: 'Username is required.' };
  }
  if (username.length < 3 || username.length > 30) {
    return { valid: false, error: 'Username must be between 3 and 30 characters.' };
  }
  if (username.includes('..')) {
    return { valid: false, error: 'Username cannot contain consecutive dots.' };
  }
  if (!USERNAME_REGEX.test(username)) {
    return {
      valid: false,
      error: 'Username may only use letters, numbers, dots, underscores, and hyphens, and must start and end with a letter or number.',
    };
  }
  if (RESERVED_USERNAMES.has(username)) {
    return { valid: false, error: 'This username is reserved and cannot be used.' };
  }
  return { valid: true, username };
}

function validateDomain(rawDomain, allowedDomains) {
  const domain = normalizeUsername(rawDomain);
  if (!domain) {
    return { valid: false, error: 'Domain is required.' };
  }
  if (!Array.isArray(allowedDomains) || !allowedDomains.includes(domain)) {
    return { valid: false, error: 'Selected domain is not supported.' };
  }
  return { valid: true, domain };
}

function validateAddress(rawAddress, allowedDomains, { allowReserved = false } = {}) {
  const address = normalizeAddress(rawAddress);
  const parts = address.split('@');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, error: 'Invalid email address format.' };
  }
  const [username, domain] = parts;

  if (username.length < 3 || username.length > 30 || username.includes('..') || !USERNAME_REGEX.test(username)) {
    return { valid: false, error: 'Invalid username in email address.' };
  }
  if (!allowReserved && RESERVED_USERNAMES.has(username)) {
    return { valid: false, error: 'Reserved username in email address.' };
  }

  const domainResult = validateDomain(domain, allowedDomains);
  if (!domainResult.valid) {
    return domainResult;
  }

  return { valid: true, address: `${username}@${domain}`, username, domain };
}

const GENERAL_LOCAL_REGEX = /^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$/;
const GENERAL_DOMAIN_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function validateAddressSyntax(rawAddress) {
  const address = normalizeAddress(rawAddress);
  const parts = address.split('@');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, error: 'Invalid email address format.' };
  }
  const [username, domain] = parts;
  if (!GENERAL_LOCAL_REGEX.test(username) || !GENERAL_DOMAIN_REGEX.test(domain)) {
    return { valid: false, error: 'Invalid email address format.' };
  }
  return { valid: true, address, username, domain };
}

function generateRandomUsername(length = 10) {
  let result = '';
  for (let i = 0; i < length; i += 1) {
    result += RANDOM_ALPHABET[crypto.randomInt(0, RANDOM_ALPHABET.length)];
  }
  return result;
}

module.exports = {
  USERNAME_REGEX,
  RESERVED_USERNAMES,
  normalizeUsername,
  normalizeAddress,
  validateUsername,
  validateDomain,
  validateAddress,
  validateAddressSyntax,
  generateRandomUsername,
};

