/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                background: '#09090b', // Zinc 950
                surface: '#18181b',    // Zinc 900
                surfaceHighlight: '#27272a', // Zinc 800
                primary: '#10b981',    // Emerald 500
                secondary: '#a1a1aa',  // Zinc 400
                accent: '#34d399',     // Emerald 400
                success: '#10b981',    // Emerald 500
                error: '#ef4444',      // Red 500
            },
            fontFamily: {
                mono: ['"JetBrains Mono"', 'monospace'],
                sans: ['Inter', 'sans-serif'],
            },
        },
    },
    plugins: [],
}
