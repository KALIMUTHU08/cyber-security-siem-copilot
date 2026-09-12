/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Background surfaces
        'bg-app':      '#0d1117',
        'bg-panel':    '#161b22',
        'bg-elevated': '#21262d',
        'bg-hover':    '#2d333b',

        // Borders
        'border-subtle':  '#21262d',
        'border-default': '#30363d',
        'border-strong':  '#484f58',

        // Text hierarchy
        'text-primary':   '#e6edf3',
        'text-secondary': '#8b949e',
        'text-muted':     '#6e7681',
        'text-disabled':  '#484f58',

        // Primary accent (interactive chrome, links, active nav)
        'accent': {
          DEFAULT: '#388bfd',
          hover:   '#4d9fff',
          muted:   '#1f4f9e',
          subtle:  '#0d2b5e',
        },

        // Copilot / AI accent (ONLY for AI elements)
        'ai': {
          DEFAULT: '#39c5cf',
          hover:   '#4dd8e3',
          muted:   '#1a6b71',
          subtle:  '#0c3c41',
        },

        // Severity colors (functional, not decorative)
        'critical': {
          DEFAULT: '#f85149',
          bg:      '#2d1113',
          border:  '#6e1a1f',
          text:    '#ffa198',
        },
        'high': {
          DEFAULT: '#e3872d',
          bg:      '#2d1a0a',
          border:  '#6e3b0a',
          text:    '#ffa55a',
        },
        'medium': {
          DEFAULT: '#d29922',
          bg:      '#2b2004',
          border:  '#5e4003',
          text:    '#f0c050',
        },
        'low': {
          DEFAULT: '#3fb950',
          bg:      '#0d2410',
          border:  '#1a5224',
          text:    '#7ee787',
        },

        // Status colors
        'status': {
          new:          '#388bfd',
          investigating:'#d29922',
          resolved:     '#3fb950',
          dismissed:    '#6e7681',
          open:         '#f85149',
          contained:    '#e3872d',
          closed:       '#6e7681',
        },
      },

      fontFamily: {
        sans: ['"IBM Plex Sans"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', '"JetBrains Mono"', 'monospace'],
      },

      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '1rem' }],
        xs:    ['0.75rem',  { lineHeight: '1rem' }],
        sm:    ['0.875rem', { lineHeight: '1.25rem' }],
        base:  ['1rem',     { lineHeight: '1.5rem' }],
        lg:    ['1.125rem', { lineHeight: '1.75rem' }],
        xl:    ['1.25rem',  { lineHeight: '1.75rem' }],
        '2xl': ['1.5rem',   { lineHeight: '2rem' }],
        '3xl': ['1.875rem', { lineHeight: '2.25rem' }],
      },

      borderRadius: {
        none:  '0',
        sm:    '2px',
        DEFAULT:'4px',
        md:    '6px',
        lg:    '8px',
        full:  '9999px',
      },

      boxShadow: {
        panel: '0 1px 3px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.3)',
        elevated: '0 4px 12px rgba(0,0,0,0.5)',
        focus: '0 0 0 2px #388bfd40',
      },

      spacing: {
        sidebar: '224px',
        topbar:  '56px',
      },

      animation: {
        'fade-in':    'fadeIn 0.15s ease-out',
        'slide-in':   'slideIn 0.2s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },

      keyframes: {
        fadeIn: {
          '0%':   { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          '0%':   { opacity: '0', transform: 'translateX(8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
      },

      transitionDuration: {
        DEFAULT: '150ms',
      },
    },
  },
  plugins: [],
}
