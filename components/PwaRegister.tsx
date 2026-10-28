"use client";
import { useEffect } from "react";

/** Registers the service worker that makes the panel installable (Chrome / Edge / Android). */
export default function PwaRegister() {
  useEffect(() => {
    if ("serviceWorker" in navigator && process.env.NODE_ENV === "production") {
      navigator.serviceWorker.register("/sw.js").catch(() => {});
    }
  }, []);
  return null;
}
