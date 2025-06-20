import {
  sanitizeBotMentions,
  sanitizeLabels,
  sanitizeCommandInput,
  validateRepositoryName,
  validateGitHubRef,
  sanitizeEnvironmentValue,
  unescapeMarkdown
} from '../../../src/utils/sanitize';

describe('Sanitize Utils', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('sanitizeBotMentions', () => {
    it('should remove bot mentions when BOT_USERNAME is set', () => {
      process.env.BOT_USERNAME = '@TestBot';
      const text = 'Hello @TestBot, can you help me?';
      expect(sanitizeBotMentions(text)).toBe('Hello TestBot, can you help me?');
    });

    it('should handle bot username without @ symbol', () => {
      process.env.BOT_USERNAME = 'TestBot';
      const text = 'Hello TestBot, can you help me?';
      expect(sanitizeBotMentions(text)).toBe('Hello TestBot, can you help me?');
    });

    it('should handle case insensitive mentions', () => {
      process.env.BOT_USERNAME = '@TestBot';
      const text = 'Hello @testbot and @TESTBOT';
      expect(sanitizeBotMentions(text)).toBe('Hello TestBot and TestBot');
    });

    it('should return original text when BOT_USERNAME is not set', () => {
      delete process.env.BOT_USERNAME;
      const text = 'Hello @TestBot';
      expect(sanitizeBotMentions(text)).toBe(text);
    });

    it('should handle empty or null text', () => {
      process.env.BOT_USERNAME = '@TestBot';
      expect(sanitizeBotMentions('')).toBe('');
      expect(sanitizeBotMentions(null as any)).toBe(null);
      expect(sanitizeBotMentions(undefined as any)).toBe(undefined);
    });
  });

  describe('sanitizeLabels', () => {
    it('should remove invalid characters from labels', () => {
      const labels = ['valid-label', 'invalid@label', 'another#invalid'];
      const result = sanitizeLabels(labels);
      expect(result).toEqual(['valid-label', 'invalidlabel', 'anotherinvalid']);
    });

    it('should allow valid label characters', () => {
      const labels = ['bug', 'feature:request', 'priority_high', 'scope-backend'];
      const result = sanitizeLabels(labels);
      expect(result).toEqual(labels);
    });

    it('should handle empty labels array', () => {
      expect(sanitizeLabels([])).toEqual([]);
    });
  });

  describe('sanitizeCommandInput', () => {
    it('should remove dangerous shell characters', () => {
      const input = 'echo `whoami` && rm -rf $HOME';
      const result = sanitizeCommandInput(input);
      expect(result).not.toContain('`');
      expect(result).not.toContain('$');
      expect(result).not.toContain('&&');
    });

    it('should remove command injection characters', () => {
      const input = 'cat file.txt; ls -la | grep secret > output.txt';
      const result = sanitizeCommandInput(input);
      expect(result).not.toContain(';');
      expect(result).not.toContain('|');
      expect(result).not.toContain('>');
    });

    it('should preserve safe command text', () => {
      const input = 'npm install express';
      expect(sanitizeCommandInput(input)).toBe('npm install express');
    });

    it('should trim whitespace', () => {
      const input = '  npm test  ';
      expect(sanitizeCommandInput(input)).toBe('npm test');
    });

    it('should handle empty input', () => {
      expect(sanitizeCommandInput('')).toBe('');
      expect(sanitizeCommandInput(null as any)).toBe(null);
    });
  });

  describe('validateRepositoryName', () => {
    it('should accept valid repository names', () => {
      const validNames = ['my-repo', 'my_repo', 'my.repo', 'MyRepo123', 'repo'];

      validNames.forEach(name => {
        expect(validateRepositoryName(name)).toBe(true);
      });
    });

    it('should reject invalid repository names', () => {
      const invalidNames = ['my repo', 'my@repo', 'my#repo', 'my/repo', 'my\\repo', ''];

      invalidNames.forEach(name => {
        expect(validateRepositoryName(name)).toBe(false);
      });
    });
  });

  describe('validateGitHubRef', () => {
    it('should accept valid GitHub refs', () => {
      const validRefs = [
        'main',
        'feature/new-feature',
        'release-1.0.0',
        'hotfix_123',
        'refs/heads/main',
        'v1.2.3'
      ];

      validRefs.forEach(ref => {
        expect(validateGitHubRef(ref)).toBe(true);
      });
    });

    it('should reject invalid GitHub refs', () => {
      const invalidRefs = ['feature..branch', 'branch with spaces', 'branch@123', 'branch#123', ''];

      invalidRefs.forEach(ref => {
        expect(validateGitHubRef(ref)).toBe(false);
      });
    });
  });

  describe('sanitizeEnvironmentValue', () => {
    it('should redact sensitive environment values', () => {
      const sensitiveKeys = [
        'GITHUB_TOKEN',
        'API_TOKEN',
        'SECRET_KEY',
        'PASSWORD',
        'AWS_ACCESS_KEY_ID',
        'ANTHROPIC_API_KEY'
      ];

      sensitiveKeys.forEach(key => {
        expect(sanitizeEnvironmentValue(key, 'actual-value')).toBe('[REDACTED]');
      });
    });

    it('should not redact non-sensitive values', () => {
      const nonSensitiveKeys = ['NODE_ENV', 'PORT', 'APP_NAME', 'LOG_LEVEL'];

      nonSensitiveKeys.forEach(key => {
        expect(sanitizeEnvironmentValue(key, 'value')).toBe('value');
      });
    });

    it('should handle case insensitive key matching', () => {
      expect(sanitizeEnvironmentValue('github_token', 'value')).toBe('[REDACTED]');
      expect(sanitizeEnvironmentValue('GITHUB_TOKEN', 'value')).toBe('[REDACTED]');
    });

    it('should detect partial key matches', () => {
      expect(sanitizeEnvironmentValue('MY_CUSTOM_TOKEN', 'value')).toBe('[REDACTED]');
      expect(sanitizeEnvironmentValue('DB_PASSWORD_HASH', 'value')).toBe('[REDACTED]');
    });
  });

  describe('unescapeMarkdown', () => {
    it('should unescape escaped newlines', () => {
      const input = 'Line 1\\nLine 2\\nLine 3';
      const expected = 'Line 1\nLine 2\nLine 3';
      expect(unescapeMarkdown(input)).toBe(expected);
    });

    it('should unescape escaped quotes', () => {
      const input = 'This is a \\"quoted\\" string and this is a \\\'single quoted\\\' string';
      const expected = 'This is a "quoted" string and this is a \'single quoted\' string';
      expect(unescapeMarkdown(input)).toBe(expected);
    });

    it('should unescape markdown characters', () => {
      const input = '\\* This is a bullet\\n\\- Another bullet\\n\\# Header\\n\\`code\\`';
      const expected = '* This is a bullet\n- Another bullet\n# Header\n`code`';
      expect(unescapeMarkdown(input)).toBe(expected);
    });

    it('should handle escaped code blocks', () => {
      const input = '\\`\\`\\`javascript\\nconst x = \\"test\\";\\n\\`\\`\\`';
      const expected = '```javascript\nconst x = "test";\n```';
      expect(unescapeMarkdown(input)).toBe(expected);
    });

    it('should handle mixed markdown escaping', () => {
      const input =
        '\\# PR Review\\n\\n\\* Issue: Code has problems\\n\\* Suggestion: Fix them\\n\\n\\`\\`\\`js\\ncode()\\n\\`\\`\\`';
      const expected =
        '# PR Review\n\n* Issue: Code has problems\n* Suggestion: Fix them\n\n```js\ncode()\n```';
      expect(unescapeMarkdown(input)).toBe(expected);
    });

    it('should handle empty or null input', () => {
      expect(unescapeMarkdown('')).toBe('');
      expect(unescapeMarkdown(null as any)).toBe(null);
      expect(unescapeMarkdown(undefined as any)).toBe(undefined);
    });

    it('should not modify already correct markdown', () => {
      const input =
        '# Header\n\n* Bullet point\n* Another bullet\n\n```javascript\nconst x = "test";\n```';
      expect(unescapeMarkdown(input)).toBe(input);
    });

    it('should handle escaped brackets and parentheses', () => {
      const input = 'Link: \\[text\\]\\(url\\) and another \\[link\\]';
      const expected = 'Link: [text](url) and another [link]';
      expect(unescapeMarkdown(input)).toBe(expected);
    });
  });
});
