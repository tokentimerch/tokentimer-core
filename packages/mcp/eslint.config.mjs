export default [
  {
    ignores: ["node_modules/**", "coverage/**", "dist/**", "vendor/**"],
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "commonjs",
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
