"use client";
import { useEffect } from "react";

/** Adds .in to .reveal elements when they enter the viewport. One observer for the page. */
export function RevealObserver() {
  useEffect(() => {
    const els = Array.from(document.querySelectorAll<HTMLElement>(".reveal:not(.in)"));
    if (!("IntersectionObserver" in window)) { els.forEach((e) => e.classList.add("in")); return; }
    const io = new IntersectionObserver(
      (entries) => entries.forEach((en) => { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } }),
      { rootMargin: "0px 0px -8% 0px", threshold: 0.05 }
    );
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  });
  return null;
}
