/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#070b14",
          card: "#0d1527",
          cardHover: "#111c34",
          border: "#1e293b",
          borderGlow: "#00f0ff33",
          cyan: "#00f0ff",
          blue: "#0284c7",
          electric: "#38bdf8",
          darkNavy: "#0a0f1d"
        },
        risk: {
          low: "#10b981",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444"
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace']
      },
      boxShadow: {
        'glow-cyan': '0 0 20px -5px rgba(0, 240, 255, 0.3)',
        'glow-blue': '0 0 20px -5px rgba(56, 189, 248, 0.3)',
        'glow-red': '0 0 20px -5px rgba(239, 68, 68, 0.35)',
      }
    },
  },
  plugins: [],
}
