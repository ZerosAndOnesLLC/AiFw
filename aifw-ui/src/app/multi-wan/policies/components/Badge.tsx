export function Badge({
  color,
  children,
}: {
  color: "cyan" | "blue" | "yellow" | "gray";
  children: React.ReactNode;
}) {
  const c = {
    cyan: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    blue: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    yellow: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    gray: "bg-gray-500/10 text-gray-400 border-gray-500/20",
  }[color];
  return (
    <span
      className={`inline-flex items-center text-[10px] px-1.5 py-0.5 rounded border font-mono ${c}`}
    >
      {children}
    </span>
  );
}
