/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pages/**/*.{js,jsx}",
    "./components/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        sand: "#f5efe6",
        slateink: "#1d293d",
        ember: "#cc5a2f",
        sage: "#7b8f6a",
      },
      fontFamily: {
        sans: ["Poppins", "ui-sans-serif", "system-ui"],
      },
      boxShadow: {
        card: "0 24px 60px rgba(29, 41, 61, 0.12)",
      },
    },
  },
  plugins: [],
};
