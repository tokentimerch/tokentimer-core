export default [
  {
    files: ["**/*.js"],
    ignores: ["node_modules/**", "coverage/**", "dist/**"],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "script",
      globals: { node: true },
    },
    rules: {
      "no-unused-vars": [
        "error",
        {
          varsIgnorePattern: "^_",
          argsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      "no-console": "off",
      "require-await": "warn",
      "prefer-const": "warn",
      "no-var": "error",
    },
  },
];
