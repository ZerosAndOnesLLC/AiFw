"use client";

import { createContext, useContext, useEffect, useRef, useState, useCallback, ReactNode } from "react";
import { getWsTicket, isAuthed } from "@/lib/api";

interface WsData {
  status: Record<string, unknown> | null;
  system: Record<string, unknown> | null;
  connections: Record<string, unknown>[];
  interfaces: Record<string, unknown>[];
  blocked: Record<string, unknown>[];
  services: Record<string, unknown>[];
  ids: Record<string, unknown> | null;
  connected: boolean;
  /// Snapshot of the rolling status-update history (up to 1800 entries,
  /// ~30 min at 1 Hz). Exposed as an imperative getter — not state — so
  /// per-frame appends don't re-render every useWs() consumer
  /// (PERF-H23 #367). Read it once when `historyLoaded` flips true and
  /// build chart data incrementally from live updates afterwards.
  getHistory: () => Record<string, unknown>[];
  historyLoaded: boolean;
}

/// Cap on buffered status-update frames (1 Hz → ~30 minutes).
const HISTORY_MAX = 1800;

const WsContext = createContext<WsData>({
  status: null, system: null, connections: [], interfaces: [], blocked: [], services: [],
  ids: null, connected: false, getHistory: () => [], historyLoaded: false,
});

export function useWs() { return useContext(WsContext); }

export function WsProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [system, setSystem] = useState<Record<string, unknown> | null>(null);
  const [connections, setConnections] = useState<Record<string, unknown>[]>([]);
  const [interfaces, setInterfaces] = useState<Record<string, unknown>[]>([]);
  const [blocked, setBlocked] = useState<Record<string, unknown>[]>([]);
  const [services, setServices] = useState<Record<string, unknown>[]>([]);
  const [ids, setIds] = useState<Record<string, unknown> | null>(null);
  const [connected, setConnected] = useState(false);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const histBuf = useRef<Record<string, unknown>[]>([]);
  const connectRef = useRef<() => void>(() => {});

  const connect = useCallback(async () => {
    if (!isAuthed()) return;
    if (wsRef.current && wsRef.current.readyState <= 1) return;

    let ticket: string;
    try {
      ticket = await getWsTicket();
    } catch {
      return;
    }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws?ticket=${ticket}`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);

        if (msg.type === "history" && Array.isArray(msg.data)) {
          histBuf.current = msg.data;
          setHistoryLoaded(true);
          const last = msg.data[msg.data.length - 1];
          if (last?.status) setStatus(last.status);
          if (last?.system) setSystem(last.system);
          if (last?.connections) setConnections(last.connections);
          if (last?.interfaces) setInterfaces(last.interfaces);
          if (last?.blocked) setBlocked(last.blocked);
          if (last?.services) setServices(last.services);
          if (last?.ids) setIds(last.ids);
          return;
        }

        if (msg.type === "status_update") {
          setStatus(msg.status);
          if (msg.system) setSystem(msg.system);
          if (msg.connections) setConnections(msg.connections);
          if (msg.interfaces) setInterfaces(msg.interfaces);
          if (msg.blocked) setBlocked(msg.blocked);
          if (msg.services) setServices(msg.services);
          if (msg.ids) setIds(msg.ids);
          // Append in place — no per-frame reallocation and no state update,
          // so history growth never triggers React re-renders (PERF-H23 #367).
          histBuf.current.push(msg);
          if (histBuf.current.length > HISTORY_MAX) histBuf.current.shift();
        }
      } catch { /* ignore */ }
    };

    ws.onclose = () => {
      setConnected(false);
      // PERF-L9 (#401): reset so consumers see a genuine false→true
      // transition when the reconnect replaces histBuf with the server's
      // fresh history — they re-seed charts from the new buffer instead
      // of ignoring the replacement (or double-handling the flip).
      setHistoryLoaded(false);
      wsRef.current = null;
      reconRef.current = setTimeout(() => connectRef.current(), 3000);
    };

    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    connectRef.current = connect;
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconRef.current) clearTimeout(reconRef.current);
    };
  }, [connect]);

  // Stable identity; returns a copy so consumers can't mutate the buffer.
  // Called rarely (chart seeding on mount / NIC change), never per frame.
  const getHistory = useCallback(() => histBuf.current.slice(), []);

  return (
    <WsContext.Provider value={{ status, system, connections, interfaces, blocked, services, ids, connected, getHistory, historyLoaded }}>
      {children}
    </WsContext.Provider>
  );
}
