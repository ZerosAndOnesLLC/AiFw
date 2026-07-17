"use client";

import { Feedback } from "@/hooks/useFeedback";

interface FeedbackBannerProps {
  feedback: Feedback;
}

export function FeedbackBanner({ feedback }: FeedbackBannerProps) {
  return (
    <div
      className={`px-4 py-3 rounded-lg text-sm border ${
        feedback.type === "success"
          ? "bg-green-500/10 border-green-500/30 text-green-400"
          : "bg-red-500/10 border-red-500/30 text-red-400"
      }`}
    >
      {feedback.msg}
    </div>
  );
}
