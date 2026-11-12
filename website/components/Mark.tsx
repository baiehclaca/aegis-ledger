import { PRODUCT_NAME } from "@/lib";

/** hairline: keep a 1.25px stroke at any display size (for large marks). */
type Props = { className?: string; title?: string; hairline?: boolean };

/**
 * Original outlined mark: a running greyhound, after the courier's token.
 * Thin 1.25 stroke, square caps, sharp joins, currentColor. Not a copy of any official insignia.
 */
export const MARK_PATHS = [
  "M30.4 12.4 L26.8 10.4 L25 10 C22.6 10.6 21.4 12.4 19.8 13.4 C16.4 12 12.6 11.4 9.6 12.4 C8.2 12.9 7.4 13.6 7.2 14.8 L8.2 17 L11 16.4 L13.4 14.8 C15.6 15.4 16.8 18.8 19.2 18.8 C20.6 18.8 21.4 17.6 22 16.2 L23.6 13.8 L26 12.8 Z",
  "M24.6 10.4 L22.6 10.8",
  "M21.6 17.2 L25.4 19.6 L29.6 19.8",
  "M19.8 18.8 L23 21.8 L26.8 22.6",
  "M8.4 17 L5.2 20.4 L1.6 21.2",
  "M10.6 16.8 L8 21.2 L4.4 23.4",
  "M7.6 13.4 C5 14.2 2.6 15.8 1.4 13.8",
];

export function Mark({ className, title, hairline = false }: Props) {
  return (
    <svg viewBox="0 0 32 32" className={className} fill="none" stroke="currentColor" strokeWidth={1.25} strokeLinecap="square" strokeLinejoin="miter" role={title ? "img" : undefined} aria-hidden={title ? undefined : true} aria-label={title}>
      {MARK_PATHS.map((d) => <path key={d} d={d} vectorEffect={hairline ? "non-scaling-stroke" : undefined} />)}
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className ?? ""}`}>
      <Mark className="h-7 w-7" />
      <span className="text-[15px] font-medium tracking-[-0.01em]">{PRODUCT_NAME}</span>
    </span>
  );
}
