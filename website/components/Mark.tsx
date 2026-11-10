type Props = { className?: string; title?: string };

/** Original outlined mark: a shield outline holding three ledger lines. Thin 1.25 stroke. */
export function Mark({ className, title }: Props) {
  return (
    <svg viewBox="0 0 32 32" className={className} fill="none" stroke="currentColor" strokeWidth={1.25} strokeLinecap="square" role={title ? "img" : undefined} aria-hidden={title ? undefined : true} aria-label={title}>
      <path d="M16 2.75 L27.25 6.5 V15.5 C27.25 22 22.5 26.75 16 29.25 C9.5 26.75 4.75 22 4.75 15.5 V6.5 Z" />
      <path d="M10 12.5 H22" />
      <path d="M10 16.5 H22" />
      <path d="M10 20.5 H18" />
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className ?? ""}`}>
      <Mark className="h-6 w-6" />
      <span className="text-[15px] font-medium tracking-[-0.01em]">Aegis Ledger</span>
    </span>
  );
}
