"use client";

import { useState } from "react";

/* ─── Active PF Rules (collapsible) ─────────────────────────────── */

export function SystemRulesPanel({ systemRules }: { systemRules: string[] }) {
  const [showSystem, setShowSystem] = useState(false);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setShowSystem(!showSystem)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-700/40 transition-colors"
      >
        <h3 className="text-sm font-medium text-white">
          Active PF Rules &mdash; {systemRules.length} rules
        </h3>
        <svg
          className={`w-4 h-4 text-gray-400 transition-transform ${showSystem ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {showSystem && (
        <div className="border-t border-gray-700 p-4">
          <p className="text-xs text-gray-500 mb-3">
            Live pf rules loaded in the kernel, including main ruleset and AiFw anchor rules.
          </p>
          <div className="bg-gray-900 rounded-lg p-4 font-mono text-xs space-y-0.5 overflow-x-auto max-h-96 overflow-y-auto">
            {systemRules.length === 0 ? (
              <div className="text-gray-500">No rules loaded</div>
            ) : systemRules.map((rule, i) => {
              const isBlock = rule.startsWith("block");
              const isPass = rule.startsWith("pass");
              const isAnchor = rule.startsWith("anchor");
              const isComment = rule.startsWith("#");
              const isScrub = rule.startsWith("scrub");
              const color = isComment
                ? "text-amber-400 font-bold"
                : isBlock
                  ? "text-red-400"
                  : isPass
                    ? "text-green-400"
                    : isAnchor
                      ? "text-blue-400"
                      : isScrub
                        ? "text-purple-400"
                        : "text-gray-400";
              return (
                <div key={i} className={`${color} whitespace-nowrap`}>
                  {!isComment && (
                    <span className="text-gray-600 mr-3 select-none">
                      {String(i + 1).padStart(3, " ")}.
                    </span>
                  )}
                  {rule}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
