import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: { extend: { colors: { ink: "#080b12", panel: "#101722", line: "#243142", mint: "#73f0c0", amber: "#f6c76b" } } },
  plugins: []
};
export default config;
