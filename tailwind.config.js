/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './backend/templates/**/*.html',
  ],
  theme: {
    extend: {
      colors: {
        background: '#090d16',
        sidebar: '#0d1322',
        card: '#111827',
        border: '#1f293d',
        primary: '#06b6d4',
        'primary-dark': '#0891b2',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        muted: '#94a3b8',
        foreground: '#f1f5f9'
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace']
      }
    }
  },
  plugins: []
}