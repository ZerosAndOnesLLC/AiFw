export function IconButton({
  onClick,
  title,
  color = "default",
  children,
}: {
  onClick: () => void;
  title: string;
  color?: "default" | "red";
  children: React.ReactNode;
}) {
  const c =
    color === "red"
      ? "bg-red-600/70 hover:bg-red-700"
      : "bg-gray-700/60 hover:bg-gray-600";
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      title={title}
      className={`${c} text-white w-7 h-7 flex items-center justify-center rounded text-xs transition-colors`}
    >
      {children}
    </button>
  );
}
