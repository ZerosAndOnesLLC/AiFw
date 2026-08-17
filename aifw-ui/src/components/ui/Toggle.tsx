"use client";

/**
 * Accessible on/off switch (QUAL-M14/M16 #449 #451). Replaces the
 * hand-rolled `<button style={{backgroundColor…}}>` toggles: `role="switch"`
 * + `aria-checked` for screen readers, keyboard-operable like any button,
 * state expressed with classes instead of inline styles.
 */
export function Toggle({
  checked,
  onChange,
  disabled = false,
  title,
  label,
  color = "green",
  className = "",
}: {
  checked: boolean;
  onChange: () => void;
  disabled?: boolean;
  /** Tooltip; defaults to Enable/Disable. */
  title?: string;
  /** Accessible name when there is no visible label next to the switch. */
  label?: string;
  color?: "green" | "blue";
  className?: string;
}) {
  const on = color === "blue" ? "bg-blue-600" : "bg-green-500";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={onChange}
      disabled={disabled}
      title={title ?? (checked ? "Disable" : "Enable")}
      className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] disabled:opacity-50 disabled:cursor-not-allowed ${checked ? on : "bg-gray-600"} ${className}`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${checked ? "translate-x-4" : "translate-x-0"}`}
      />
    </button>
  );
}
