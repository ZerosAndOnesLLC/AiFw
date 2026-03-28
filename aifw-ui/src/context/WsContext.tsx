"use client";

import { createContext, useContext, useEffect, useRef, useState, useCallback, ReactNode } from "react";

interface WsData {
  status: Record<string, unknown> | null;
  system: Record<string, unknown> | null;
  connections: Record<string, unknown>[];
  interfaces: Record<string, unknown>[];
  connected: boolean;
  history: Record<string, unknown>[];
  historyLoaded: boolean;
}

const WsContext = createContext<WsData>({
  status: null, system: null, connections: [], interfaces: [],
  connected: false, history: [], historyLoaded: false,
});

export function useWs() { return useContext(WsContext); }

export function WsProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [system, setSystem] = useState<Record<string, unknown> | null>(null);
  const [connections, setConnections] = useState<Record<string, unknown>[]>([]);
  const [interfaces, setInterfaces] = useState<Record<string, unknown>[]>([]);
  const [connected, setConnected] = useState(false);
  const [history, setHistory] = useState<Record<string, unknown>[]>([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const histBuf = useRef<Record<string, unknown>[]>([]);

  const connect = useCallback(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    if (wsRef.current && wsRef.current.readyState <= 1) return; // already open/connecting

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);

        if (msg.type === "history" && Array.isArray(msg.data)) {
          histBuf.current = msg.data;
          setHistory(msg.data);
          setHistoryLoaded(true);
          // Set latest values from last entry
          const last = msg.data[msg.data.length - 1];
          if (last?.status) setStatus(last.status);
          if (last?.system) setSystem(last.system);
          if (last?.connections) setConnections(last.connections);
          if (last?.interfaces) setInterfaces(last.interfaces);
          return;
        }

        if (msg.type === "status_update") {
          setStatus(msg.status);
          if (msg.system) setSystem(msg.system);
          if (msg.connections) setConnections(msg.connections);
          if (msg.interfaces) setInterfaces(msg.interfaces);
          // Append to history buffer
          histBuf.current = [...histBuf.current, msg].slice(-1800);
          setHistory(histBuf.current);
        }
      } catch { /* ignore */ }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
      reconRef.current = setTimeout(connect, 3000);
    };

    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconRef.current) clearTimeout(reconRef.current);
    };
  }, [connect]);

  return (
    <WsContext.Provider value={{ status, system, connections, interfaces, connected, history, historyLoaded }}>
      {children}
    </WsContext.Provider>
  );
}
