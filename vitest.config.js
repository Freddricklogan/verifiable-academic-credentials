import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.js'],
    environment: 'node',
    setupFiles: ['tests/setup.js'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      // Pure + crypto logic. The DOM layer (ui/main/exec-shell) is exercised by
      // the Playwright smoke test, not by unit tests.
      include: [
        'src/encoding.js',
        'src/canonicalize.js',
        'src/did.js',
        'src/statuslist.js',
        'src/ledger.js',
        'src/credential.js',
        'src/crypto.js',
        'src/verify.js'
      ]
    }
  }
});
