import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { sanitizeEmailHtml, createSnippet } = require('../server/sanitize');

describe('HTML sanitizer and snippet helper', () => {
  it('blocks remote images by moving src to data-src and preserves safe attributes', () => {
    const dirty = '<p>Hello</p><img src="https://tracker.example/pixel.png" alt="Logo" width="120" height="40">';
    const clean = sanitizeEmailHtml(dirty);
    expect(clean).toContain('data-src="https://tracker.example/pixel.png"');
    expect(clean).not.toMatch(/\ssrc=/i);
    expect(clean).toContain('alt="Logo"');
    expect(clean).toContain('width="120"');
  });

  it('adds target="_blank" and rel="noopener noreferrer nofollow" to safe links', () => {
    const clean = sanitizeEmailHtml('<a href="https://example.com/verify">Verify</a>');
    expect(clean).toContain('href="https://example.com/verify"');
    expect(clean).toContain('target="_blank"');
    expect(clean).toContain('rel="noopener noreferrer nofollow"');
  });

  it('keeps allowed inline styles and strips disallowed style properties', () => {
    const dirty = '<p style="color: #112233; text-align: center; position: fixed; top: 0;">Styled</p>';
    const clean = sanitizeEmailHtml(dirty);
    expect(clean).toContain('color:#112233');
    expect(clean).toContain('text-align:center');
    expect(clean).not.toContain('position');
    expect(clean).not.toContain('top');
  });

  it('neutralizes at least 12 distinct XSS payloads', () => {
    const payloads = [
      '<script>alert(1)</script><p>Hi</p>',
      '<img src="https://example.com/x.jpg" onerror="alert(2)">',
      '<a href="javascript:alert(3)">Click</a>',
      '<iframe src="https://evil.example/frame.html"></iframe>',
      '<svg onload="alert(5)"><circle r="10"></circle></svg>',
      '<div onmouseover="fetch(\'https://evil.example\')">Hover</div>',
      '<a href="  JaVaScRiPt:alert(7)">Weird Link</a>',
      '<object data="data:text/html,<script>alert(8)</script>"></object>',
      '<embed src="https://evil.example/exploit.swf">',
      '<form action="https://evil.example"><input type="submit"></form><meta http-equiv="refresh" content="0;url=javascript:alert(10)">',
      '<style>body{background:url("javascript:alert(11)")}</style><p>Safe</p>',
      '<img src="javascript:alert(12)">',
    ];

    for (const payload of payloads) {
      const clean = sanitizeEmailHtml(payload);
      expect(clean.toLowerCase()).not.toContain('<script');
      expect(clean.toLowerCase()).not.toContain('<iframe');
      expect(clean.toLowerCase()).not.toContain('<svg');
      expect(clean.toLowerCase()).not.toContain('<object');
      expect(clean.toLowerCase()).not.toContain('<embed');
      expect(clean.toLowerCase()).not.toContain('<form');
      expect(clean.toLowerCase()).not.toContain('<meta');
      expect(clean.toLowerCase()).not.toContain('<style');
      expect(clean.toLowerCase()).not.toContain('javascript:');
      expect(clean.toLowerCase()).not.toContain('onerror');
      expect(clean.toLowerCase()).not.toContain('onload');
      expect(clean.toLowerCase()).not.toContain('onmouseover');
    }
  });

  it('builds a 120-char plain-text snippet from text or HTML fallback', () => {
    const longText = 'Hello   world\n\n' + 'x'.repeat(150);
    const snippet = createSnippet(longText, '');
    expect(snippet.length).toBe(120);
    expect(snippet.startsWith('Hello world ')).toBe(true);

    const htmlOnly = createSnippet('', '<div><h1>Welcome</h1><p>Confirm   your account today.</p></div>');
    expect(htmlOnly).toBe('WelcomeConfirm your account today.');
  });
});
