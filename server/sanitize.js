'use strict';

const sanitizeHtml = require('sanitize-html');

const ALLOWED_TAGS = [
  'p',
  'div',
  'span',
  'br',
  'hr',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'ul',
  'ol',
  'li',
  'dl',
  'dt',
  'dd',
  'table',
  'thead',
  'tbody',
  'tfoot',
  'tr',
  'th',
  'td',
  'caption',
  'a',
  'blockquote',
  'pre',
  'code',
  'b',
  'i',
  'u',
  'strong',
  'em',
  's',
  'del',
  'sub',
  'sup',
  'img',
];

const STYLE_ALLOWED_TAGS = [
  'p',
  'div',
  'span',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'ul',
  'ol',
  'li',
  'table',
  'thead',
  'tbody',
  'tfoot',
  'tr',
  'th',
  'td',
  'a',
  'blockquote',
  'pre',
  'code',
  'b',
  'i',
  'u',
  'strong',
  'em',
];

const ALLOWED_ATTRIBUTES = {
  a: ['href', 'title', 'target', 'rel', 'style'],
  img: ['alt', 'width', 'height', 'data-src'],
  table: ['align', 'style'],
  thead: ['align', 'style'],
  tbody: ['align', 'style'],
  tfoot: ['align', 'style'],
  tr: ['align', 'style'],
  th: ['align', 'colspan', 'rowspan', 'style'],
  td: ['align', 'colspan', 'rowspan', 'style'],
};

for (const tag of STYLE_ALLOWED_TAGS) {
  if (!ALLOWED_ATTRIBUTES[tag]) {
    ALLOWED_ATTRIBUTES[tag] = ['style'];
  }
}

const COLOR_PATTERNS = [
  /^#[0-9a-fA-F]{3,8}$/,
  /^rgb\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*\)$/,
  /^rgba\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*(?:0|1|0?\.\d+)\s*\)$/,
  /^[a-zA-Z]{1,20}$/,
];

const ALLOWED_STYLES = {
  '*': {
    color: COLOR_PATTERNS,
    'background-color': COLOR_PATTERNS,
    'font-size': [/^\d+(?:\.\d+)?(?:px|em|rem|%)$/],
    'font-weight': [/^(?:normal|bold|bolder|lighter|[1-9]00)$/],
    'text-align': [/^(?:left|right|center|justify)$/],
  },
};

const SAFE_IMAGE_URL_REGEX = /^https?:\/\/[^\s"'<>]+$/i;

function sanitizeEmailHtml(dirtyHtml) {
  if (!dirtyHtml || typeof dirtyHtml !== 'string') {
    return '';
  }

  return sanitizeHtml(dirtyHtml, {
    allowedTags: ALLOWED_TAGS,
    allowedAttributes: ALLOWED_ATTRIBUTES,
    allowedStyles: ALLOWED_STYLES,
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: {
      a: ['http', 'https', 'mailto'],
    },
    allowProtocolRelative: false,
    disallowedTagsMode: 'discard',
    nonTextTags: ['style', 'script', 'textarea', 'option', 'noscript', 'iframe', 'object', 'embed'],
    transformTags: {
      a: (tagName, attribs) => {
        const nextAttribs = { ...attribs };
        nextAttribs.target = '_blank';
        nextAttribs.rel = 'noopener noreferrer nofollow';
        return { tagName, attribs: nextAttribs };
      },
      img: (tagName, attribs) => {
        const nextAttribs = {};
        if (attribs.alt !== undefined) nextAttribs.alt = attribs.alt;
        if (attribs.width !== undefined) nextAttribs.width = attribs.width;
        if (attribs.height !== undefined) nextAttribs.height = attribs.height;

        const candidateSrc = typeof attribs.src === 'string'
          ? attribs.src.trim()
          : typeof attribs['data-src'] === 'string'
            ? attribs['data-src'].trim()
            : '';

        if (candidateSrc && SAFE_IMAGE_URL_REGEX.test(candidateSrc)) {
          nextAttribs['data-src'] = candidateSrc;
        }

        return { tagName, attribs: nextAttribs };
      },
    },
  });
}

function stripTagsToText(html) {
  if (!html || typeof html !== 'string') return '';
  return sanitizeHtml(html, {
    allowedTags: [],
    allowedAttributes: {},
    nonTextTags: ['style', 'script', 'textarea', 'option', 'noscript', 'iframe', 'object', 'embed'],
  });
}

function createSnippet(text, html = '') {
  const source = (text && String(text).trim()) ? String(text) : stripTagsToText(html);
  return source.replace(/\s+/g, ' ').trim().slice(0, 120);
}

module.exports = {
  sanitizeEmailHtml,
  createSnippet,
  stripTagsToText,
};
