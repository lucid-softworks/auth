import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  base: process.env.VITE_BASE_PATH ?? "/auth/",
  plugins: [react(), tailwindcss()],
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: "docs-readme", test: /[\\/]README\.md\?raw$/ },
            { name: "docs-compatibility", test: /[\\/]COMPATIBILITY\.md\?raw$/ },
            { name: "docs-guides", test: /[\\/]docs[\\/].+\.md\?raw$/ },
            { name: "tanstack-router", test: /node_modules[\\/]@tanstack[\\/]/ },
            { name: "react", test: /node_modules[\\/](?:react|react-dom|scheduler)[\\/]/ },
            { name: "icons", test: /node_modules[\\/]lucide-react[\\/]/ },
            {
              name: "markdown",
              test: /node_modules[\\/](?:react-markdown|remark-|rehype-|unified|micromark|mdast-|hast-|unist-|vfile|highlight\.js|property-information|space-separated-tokens|comma-separated-tokens)[\\/]/,
            },
            { name: "vendor", test: /node_modules[\\/]/ },
          ],
        },
      },
    },
  },
  server: {
    fs: {
      allow: [fileURLToPath(new URL("..", import.meta.url))],
    },
  },
});
