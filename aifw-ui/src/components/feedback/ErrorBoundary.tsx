"use client";

import { Component, ErrorInfo, ReactNode } from "react";
import { ErrorFallback } from "./ErrorFallback";

interface Props {
  children: ReactNode;
  /** Label for the fallback heading, e.g. "Sidebar", "Traffic chart". */
  scope?: string;
  /** Render a smaller fallback (widgets, banners). */
  compact?: boolean;
  /** Custom fallback; receives the error and a reset callback. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
  /** Change this to force a reset (e.g. the current pathname). */
  resetKey?: unknown;
}

interface State {
  error: Error | null;
}

/**
 * Widget-level error boundary (#452). Next.js `error.tsx` files isolate a
 * whole route segment; this isolates anything smaller — a dashboard card,
 * the sidebar, a banner — so one broken widget doesn't blank the page.
 * Resets automatically when `resetKey` changes.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface in the console (and thus any error reporting) with the
    // component stack; the fallback UI handles the operator side.
    console.error(`[ErrorBoundary${this.props.scope ? `:${this.props.scope}` : ""}]`, error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.reset();
    }
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (error) {
      if (this.props.fallback) return this.props.fallback(error, this.reset);
      return (
        <ErrorFallback
          error={error}
          reset={this.reset}
          scope={this.props.scope}
          compact={this.props.compact}
        />
      );
    }
    return this.props.children;
  }
}
