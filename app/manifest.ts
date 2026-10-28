import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "B24-engine",
    short_name: "B24-engine",
    description: "B24-engine: local domain recon and OSINT workbench",
    start_url: "/",
    scope: "/",
    display: "standalone",
    background_color: "#0a0f16",
    theme_color: "#0a0f16",
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
      { src: "/icons/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
  };
}
