import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
      },
      colors: {
        sv: {
          app: "#0B0F1A",
          sidebar: "#0A0E17",
          card: "#111827",
          border: "#1F2937",
          "border-muted": "#263244",
          accent: "#4F46E5",
          "accent-hover": "#6366F1",
          success: "#22C55E",
          warning: "#F59E0B",
          danger: "#EF4444",
          text: "#F8FAFC",
          "text-secondary": "#CBD5E1",
          muted: "#64748B",
        },
      },
      boxShadow: {
        sv: "0 1px 2px rgba(0, 0, 0, 0.45), 0 0 0 1px rgba(31, 41, 55, 0.5)",
        "sv-card": "0 1px 3px rgba(0, 0, 0, 0.35)",
      },
      maxWidth: {
        content: "1280px",
      },
    },
  },
  plugins: [],
};

export default config;
