module.exports = {
  env: {
    browser: true,
    node: true,
  },
  extends: "airbnb",
  parserOptions: {},
  plugins: ["ejs-js"],
  ignorePatterns: ["temp.js", "/**/*.ejs", "node_modules/**/*"],
  validate: [
    {
      language: "html",
      autoFix: true,
    },
    {
      language: "javascript",
      autoFix: true,
    },
    {
      language: "javascriptreact",
      autoFix: true,
    },
  ],
  rules: {
    "arrow-body-style": 0,
    "consistent-return": 1,
    "func-names": 0,
    "array-bracket-newline": "consistent",
    "lines-around-comment": [
      2,
      {
        allowBlockStart: true,
        allowObjectStart: true,
        beforeBlockComment: true,
        beforeLineComment: true,
      },
    ],
    "lines-around-directive": 0,
    "max-len": 0,
    "no-mixed-operators": [
      2,
      {
        allowSamePrecedence: true,
      },
    ],
    "no-param-reassign": [
      2,
      {
        props: false,
      },
    ],
    "no-plusplus": 0,
    "no-tabs": 0,
    "no-undef": 0,
    "no-use-before-define": 0,
    "prefer-promise-reject-errors": 2,
    radix: [2, "as-needed"],
    strict: 0,
    "valid-jsdoc": 2,
    "space-before-function-paren": 0,
    yoda: 0,
    "no-alert": 0,
    "class-methods-use-this": 0,
    "no-param-reassign": 1,
    "no-prototype-builtins": 0,
    semi: [2, "never"],
  },
}
