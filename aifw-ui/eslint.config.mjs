import nextConfig from "eslint-config-next";

const config = [
  ...nextConfig,
  {
    ignores: [".next/**", "out/**", "node_modules/**", "next-env.d.ts"],
  },
  {
    // Regression guard for #428 (QUAL-H8): pages must stay presentational.
    // Move data-fetching to src/lib/api/<resource>.ts + src/hooks/, and big
    // JSX blocks to route-local components/, instead of growing page.tsx.
    files: ["src/app/**/page.tsx"],
    rules: {
      "max-lines": ["error", { max: 1000, skipBlankLines: false, skipComments: false }],
    },
  },
];

export default config;
