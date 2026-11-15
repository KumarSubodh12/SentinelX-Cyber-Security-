import type { Config } from "tailwindcss";

// Colours are CSS variables holding "R G B" channels so Tailwind opacity modifiers (bg-panel/50) work.
const c = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        page: c("page"),
        panel: c("panel"),
        raised: c("raised"),
        line: c("line"),
        ink: { DEFAULT: c("ink"), 2: c("ink-2"), 3: c("ink-3") },
        focus: c("focus"),
        good: c("good"),
        sim: c("sim"),
        sev: {
          critical: c("sev-critical"),
          high: c("sev-high"),
          medium: c("sev-medium"),
          low: c("sev-low"),
          info: c("sev-info"),
        },
        series: { 1: c("series-1"), 2: c("series-2"), 3: c("series-3") },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      borderRadius: { DEFAULT: "6px", md: "6px", lg: "8px" },
      keyframes: {
        beacon: {
          "0%": { transform: "scale(0.6)", opacity: "0.8" },
          "100%": { transform: "scale(2.2)", opacity: "0" },
        },
        slidein: {
          from: { transform: "translateX(24px)", opacity: "0" },
          to: { transform: "translateX(0)", opacity: "1" },
        },
      },
      animation: {
        beacon: "beacon 1.4s ease-out 1",
        slidein: "slidein 160ms ease-out",
      },
    },
  },
  plugins: [],
};

export default config;
