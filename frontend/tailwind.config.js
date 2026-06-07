/** @type {import('tailwindcss').Config} */
const config = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0d0d0d",
        card: "#191919",
        accent: "#a290e5",
      }
    },
  },
  plugins: [],
}

export default config
