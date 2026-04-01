import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import jsxA11y from 'eslint-plugin-jsx-a11y';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import prettier from 'eslint-config-prettier';
import unusedImports from 'eslint-plugin-unused-imports'; // <-- ADD THIS

export default [
  // Ignore built assets
  { ignores: ['dist/**'] },
  // Base JS/JSX configuration
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'module',
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
      globals: {
        browser: true,
        es2021: true,
        node: true,
      },
    },
    plugins: {
      react,
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y,
      'unused-imports': unusedImports, // <-- ADD THIS
    },
    rules: {
      // Unused imports/vars: SUPERCHARGED
      'unused-imports/no-unused-imports': 'error',
      'unused-imports/no-unused-vars': [
        'warn',
        {
          vars: 'all',
          varsIgnorePattern: '^_',
          args: 'after-used',
          argsIgnorePattern: '^_',
        },
      ],
      // React
      'react/react-in-jsx-scope': 'off',
      'react/prop-types': 'off',
      'react/jsx-uses-react': 'off',
      'react/jsx-uses-vars': 'error',
      'react/no-unescaped-entities': 'warn',
      'react/display-name': 'warn',

      // React Hooks
      'react-hooks/rules-of-hooks': 'warn',
      'react-hooks/exhaustive-deps': 'warn',

      // A11y (keep minimal noise)
      'jsx-a11y/anchor-is-valid': 'warn',
      'jsx-a11y/click-events-have-key-events': 'off',
      'jsx-a11y/no-static-element-interactions': 'off',
      'jsx-a11y/alt-text': 'off',
      'jsx-a11y/aria-props': 'off',
      'jsx-a11y/aria-proptypes': 'off',
      'jsx-a11y/aria-unsupported-elements': 'off',
      'jsx-a11y/role-has-required-aria-props': 'off',
      'jsx-a11y/role-supports-aria-props': 'off',

      // General code quality (silence noise for CI)
      'no-unused-vars': 'off', // handled by unused-imports plugin
      'no-console': 'off',
      'prefer-const': 'warn',
      'no-var': 'error',
      'object-shorthand': 'warn',
      'prefer-template': 'warn',
      'template-curly-spacing': 'error',
      'arrow-spacing': 'error',
      'no-duplicate-imports': 'warn',
      'no-useless-rename': 'error',
      'prefer-destructuring': ['warn', { object: true, array: false }],
      'no-else-return': 'warn',
      'no-return-assign': 'warn',
      'no-self-compare': 'warn',
      'no-unmodified-loop-condition': 'warn',
      'no-useless-call': 'warn',
      'no-useless-concat': 'warn',
      'no-useless-return': 'warn',
      'require-await': 'warn',
      yoda: 'warn',

      // Style (defer to Prettier entirely)
      indent: 'off',
      'linebreak-style': 'off',
      quotes: 'off',
      semi: 'off',
      'comma-dangle': 'off',
      'object-curly-spacing': 'off',
      'array-bracket-spacing': 'off',
      'computed-property-spacing': 'off',
      'space-before-blocks': 'off',
      'keyword-spacing': 'off',
      'space-infix-ops': 'off',
      'space-before-function-paren': 'off',
      'func-call-spacing': 'off',
      'no-multiple-empty-lines': 'off',
      'eol-last': 'off',
      'no-trailing-spaces': 'off',
    },
    settings: {
      react: { version: 'detect' },
    },
  },

  // TypeScript config (only TS/TSX files)
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'module',
      parser: tsparser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        project: false,
      },
      globals: {
        browser: true,
        es2021: true,
        node: true,
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
      react,
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y,
      'unused-imports': unusedImports, // <-- ADD THIS
    },
    rules: {
      // Unused imports/vars: SUPERCHARGED
      'unused-imports/no-unused-imports': 'error',
      'unused-imports/no-unused-vars': [
        'warn',
        {
          vars: 'all',
          varsIgnorePattern: '^_',
          args: 'after-used',
          argsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/indent': 'off',
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'jsx-a11y/anchor-is-valid': 'warn',
    },
    settings: {
      react: { version: 'detect' },
    },
  },

  // Tests
  {
    files: ['**/*.test.{js,jsx,ts,tsx}', '**/*.spec.{js,jsx,ts,tsx}'],
    rules: {
      'no-console': 'off',
    },
  },

  // Prettier last (kept for compatibility; all style rules off above)
  prettier,
];
