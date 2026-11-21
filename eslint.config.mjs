// ESLint 扁平配置：只做"能真接住 bug"的规则，不做风格警察。
// 目的：Worker / Pages 函数是跑到 1 亿请求量的代码，宁可在 CI 里吵，也不要在线上静默。
export default [
  {
    files: ["doh/worker.tpl.js", "pages/**/*.js", "tests/**/*.mjs", "serve/**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: {
        Request: "readonly", Response: "readonly", Headers: "readonly",
        URL: "readonly", URLSearchParams: "readonly", Buffer: "readonly",
        caches: "readonly", crypto: "readonly", console: "readonly",
        process: "readonly", globalThis: "readonly", fetch: "readonly",
        DataView: "readonly", Uint8Array: "readonly", TextDecoder: "readonly",
        TextEncoder: "readonly", atob: "readonly", btoa: "readonly",
        AbortController: "readonly", setTimeout: "readonly", clearTimeout: "readonly",
        setInterval: "readonly", clearInterval: "readonly", queueMicrotask: "readonly",
        // 构建期注入的占位符（tools/build_doh.py 会替换成真数据）
        __T1__: "readonly", __T2__: "readonly", __ALLOW_TEXT__: "readonly",
        __EP_TEXT__: "readonly", __WILD_TEXT__: "readonly", __VERSION__: "readonly",
      },
    },
    rules: {
      "no-undef": "error",              // 拼错变量名 = 线上 500
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      "no-dupe-keys": "error",
      "no-dupe-args": "error",
      "no-unreachable": "error",        // return 之后的死代码
      "no-const-assign": "error",
      "no-func-assign": "error",
      "no-self-compare": "error",
      "no-unsafe-negation": "error",
      "no-fallthrough": "error",        // 报文解析里漏 break 极其致命
      "eqeqeq": ["warn", "smart"],
      "no-empty": ["warn", { allowEmptyCatch: true }],
    },
  },
];
