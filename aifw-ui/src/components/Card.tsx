interface CardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: "up" | "down" | "neutral";
  color?: "blue" | "green" | "red" | "yellow" | "cyan";
  icon?: React.ReactNode;
}

const colorMap = {
  blue: "text-blue-400",
  green: "text-green-400",
  red: "text-red-400",
  yellow: "text-yellow-400",
  cyan: "text-cyan-400",
};

export default function Card({ title, value, subtitle, color = "blue", icon }: CardProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 hover:bg-[var(--bg-card-hover)] transition-colors">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">{title}</span>
        {icon && <span className={`${colorMap[color]} opacity-70`}>{icon}</span>}
      </div>
      <div className={`text-2xl font-bold ${colorMap[color]}`}>{value}</div>
      {subtitle && <div className="text-xs text-[var(--text-muted)] mt-1">{subtitle}</div>}
    </div>
  );
}
