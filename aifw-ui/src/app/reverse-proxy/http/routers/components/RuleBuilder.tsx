"use client";

import type { Dispatch, SetStateAction } from "react";
import { type RuleCondition, buildRuleString, parseRuleToConditions } from "@/lib/api/reverse-proxy/routers";

const inputCls =
  "w-full bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors";
const labelCls = "block text-xs text-[var(--text-muted)] mb-1";

const CONDITION_TYPES: { value: RuleCondition["type"]; label: string; placeholder: string }[] = [
  { value: "Host", label: "Host", placeholder: "example.com" },
  { value: "PathPrefix", label: "PathPrefix", placeholder: "/api" },
  { value: "Path", label: "Path", placeholder: "/exact/path" },
  { value: "Method", label: "Method", placeholder: "GET" },
  { value: "Headers", label: "Headers", placeholder: "X-Custom: value" },
  { value: "ClientIP", label: "ClientIP", placeholder: "192.168.1.0/24" },
];

interface RuleBuilderProps {
  ruleMode: "visual" | "raw";
  ruleConditions: RuleCondition[];
  ruleOperators: string[];
  ruleRaw: string;
  setRuleMode: Dispatch<SetStateAction<"visual" | "raw">>;
  setRuleConditions: Dispatch<SetStateAction<RuleCondition[]>>;
  setRuleOperators: Dispatch<SetStateAction<string[]>>;
  setRuleRaw: Dispatch<SetStateAction<string>>;
  /// Surfaces "cannot parse" errors on the page-level feedback banner.
  showError: (msg: string) => void;
}

export function RuleBuilder({
  ruleMode,
  ruleConditions,
  ruleOperators,
  ruleRaw,
  setRuleMode,
  setRuleConditions,
  setRuleOperators,
  setRuleRaw,
  showError,
}: RuleBuilderProps) {
  /* -- Rule builder actions ----------------------------------------- */

  const addCondition = () => {
    setRuleConditions((prev) => [...prev, { type: "Host", value: "" }]);
    if (ruleConditions.length > 0) {
      setRuleOperators((prev) => [...prev, "&&"]);
    }
  };

  const removeCondition = (idx: number) => {
    setRuleConditions((prev) => prev.filter((_, i) => i !== idx));
    setRuleOperators((prev) => {
      const next = [...prev];
      if (idx === 0 && next.length > 0) {
        next.splice(0, 1);
      } else if (idx > 0) {
        next.splice(idx - 1, 1);
      }
      return next;
    });
  };

  const updateConditionType = (idx: number, type: RuleCondition["type"]) => {
    setRuleConditions((prev) => prev.map((c, i) => (i === idx ? { ...c, type } : c)));
  };

  const updateConditionValue = (idx: number, value: string) => {
    setRuleConditions((prev) => prev.map((c, i) => (i === idx ? { ...c, value } : c)));
  };

  const toggleOperator = (idx: number) => {
    setRuleOperators((prev) =>
      prev.map((op, i) => (i === idx ? (op === "&&" ? "||" : "&&") : op))
    );
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className={labelCls + " mb-0"}>Rule *</label>
        <div className="flex items-center bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md overflow-hidden">
          <button
            type="button"
            onClick={() => {
              if (ruleMode === "raw") {
                // Switching from raw to visual: try to parse
                const { conditions, operators } = parseRuleToConditions(ruleRaw);
                if (conditions.length > 0 || !ruleRaw.trim()) {
                  setRuleConditions(conditions);
                  setRuleOperators(operators);
                  setRuleMode("visual");
                } else {
                  // Can't parse, stay in raw
                  showError("Cannot parse rule into visual conditions. Edit manually.");
                }
              } else {
                setRuleMode("visual");
              }
            }}
            className={`px-3 py-1 text-xs font-medium transition-colors ${
              ruleMode === "visual"
                ? "bg-blue-600 text-white"
                : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            Visual
          </button>
          <button
            type="button"
            onClick={() => {
              if (ruleMode === "visual") {
                // Switching from visual to raw: serialize conditions
                setRuleRaw(buildRuleString(ruleConditions, ruleOperators));
              }
              setRuleMode("raw");
            }}
            className={`px-3 py-1 text-xs font-medium transition-colors ${
              ruleMode === "raw"
                ? "bg-blue-600 text-white"
                : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            Raw
          </button>
        </div>
      </div>

      {ruleMode === "visual" ? (
        <div className="space-y-2">
          {ruleConditions.length === 0 && (
            <p className="text-xs text-[var(--text-muted)] py-2">No conditions yet. Add one below.</p>
          )}

          {ruleConditions.map((cond, idx) => (
            <div key={idx}>
              {/* Operator between rows */}
              {idx > 0 && (
                <div className="flex items-center justify-center py-1">
                  <button
                    type="button"
                    onClick={() => toggleOperator(idx - 1)}
                    className="px-3 py-0.5 text-xs font-mono font-bold rounded border transition-colors bg-[var(--bg-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:border-blue-500/40 hover:text-blue-400"
                  >
                    {ruleOperators[idx - 1] === "||" ? "OR" : "AND"}
                  </button>
                </div>
              )}

              {/* Condition row */}
              <div className="flex items-center gap-2">
                <select
                  value={cond.type}
                  onChange={(e) => updateConditionType(idx, e.target.value as RuleCondition["type"])}
                  className="bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-2 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500 w-36 shrink-0"
                >
                  {CONDITION_TYPES.map((ct) => (
                    <option key={ct.value} value={ct.value}>
                      {ct.label}
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={cond.value}
                  onChange={(e) => updateConditionValue(idx, e.target.value)}
                  placeholder={CONDITION_TYPES.find((ct) => ct.value === cond.type)?.placeholder || "value"}
                  className={inputCls}
                />
                <button
                  type="button"
                  onClick={() => removeCondition(idx)}
                  className="text-[var(--text-muted)] hover:text-red-400 transition-colors p-1 shrink-0"
                  title="Remove condition"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
          ))}

          <button
            type="button"
            onClick={addCondition}
            className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors mt-1"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Condition
          </button>

          {/* Rule preview */}
          {ruleConditions.length > 0 && (
            <div className="mt-2 p-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md">
              <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider block mb-1">Preview</span>
              <code className="text-xs text-[var(--text-secondary)] font-mono break-all">
                {buildRuleString(ruleConditions, ruleOperators) || "(empty)"}
              </code>
            </div>
          )}
        </div>
      ) : (
        <textarea
          value={ruleRaw}
          onChange={(e) => setRuleRaw(e.target.value)}
          placeholder='Host(`example.com`) && PathPrefix(`/api`)'
          rows={3}
          className={inputCls + " font-mono resize-y"}
        />
      )}
    </div>
  );
}
