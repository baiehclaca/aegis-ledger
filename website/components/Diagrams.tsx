/** Original hairline diagrams. Decorative; meaning is always also given in text. */

export function AgreementDiagram({ className = "" }: { className?: string }) {
  // Five independent nodes around a ring agree; agreed entries append to a chain.
  const cx = 230, cy = 230, r = 150;
  const nodes = Array.from({ length: 5 }, (_, i) => {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / 5;
    return [cx + r * Math.cos(a), cy + r * Math.sin(a)] as const;
  });
  return (
    <svg viewBox="0 0 900 460" className={`draw ${className}`} fill="none" stroke="currentColor" strokeWidth={1} aria-hidden>
      <circle cx={cx} cy={cy} r={r} pathLength={1} opacity={0.35} />
      {nodes.map(([x, y], i) =>
        nodes.slice(i + 1).map(([x2, y2], j) => (
          <line key={`${i}-${j}`} x1={x} y1={y} x2={x2} y2={y2} pathLength={1} className="d2" opacity={0.22} />
        ))
      )}
      {nodes.map(([x, y], i) => (
        <rect key={i} x={x - 9} y={y - 9} width={18} height={18} pathLength={1} fill="#0b0c0d" />
      ))}
      <path d={`M${cx + r + 20} ${cy} H520`} pathLength={1} className="d3" />
      {Array.from({ length: 5 }, (_, i) => (
        <g key={i}>
          <rect x={520 + i * 74} y={cy - 26} width={56} height={52} pathLength={1} className="d3" fill="#0b0c0d" />
          <path d={`M${532 + i * 74} ${cy - 8} H${564 + i * 74} M${532 + i * 74} ${cy + 4} H${556 + i * 74}`} pathLength={1} className="d4" opacity={0.6} />
          {i < 4 && <path d={`M${576 + i * 74} ${cy} H${594 + i * 74}`} pathLength={1} className="d4" />}
        </g>
      ))}
    </svg>
  );
}

export function LayerDiagram({ className = "" }: { className?: string }) {
  // Existing systems keep documents; the ledger layer above holds only hashes and events.
  return (
    <svg viewBox="0 0 900 350" className={`draw ${className}`} fill="none" stroke="currentColor" strokeWidth={1} aria-hidden>
      <rect x={40} y={30} width={820} height={70} pathLength={1} />
      {Array.from({ length: 4 }, (_, i) => (
        <g key={i}>
          <rect x={60 + i * 210} y={230} width={170} height={80} pathLength={1} className="d2" opacity={0.7} />
          <path d={`M${145 + i * 210} 230 V100`} className="dash" strokeDasharray="3 5" opacity={0.5} />
          <text x={75 + i * 210} y={290} fontSize={13} fill="currentColor" stroke="none" opacity={0.7}>{["Supply records", "Access systems", "Document stores", "Partner systems"][i]}</text>
        </g>
      ))}
      {Array.from({ length: 10 }, (_, i) => (
        <path key={i} d={`M${70 + i * 80} 52 H${110 + i * 80}`} pathLength={1} className="d4" opacity={0.6} />
      ))}
      <text x={70} y={84} fontSize={13} fill="currentColor" stroke="none" opacity={0.8}>Shared ledger: identifiers, timestamps, status changes, document hashes</text>
      <text x={60} y={334} fontSize={12} fill="currentColor" stroke="none" opacity={0.5}>Full documents stay here</text>
    </svg>
  );
}
