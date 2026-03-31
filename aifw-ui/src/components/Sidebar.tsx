"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";

interface NavChild { href: string; label: string; }
interface NavItem {
  href?: string;
  label: string;
  icon: string;
  color: string;
  children?: NavChild[];
  dynamicChildren?: boolean;
}

const navItems: NavItem[] = [
  // Monitoring at top — dashboard, traffic, connections, threats, logs
  {
    label: "Monitoring",
    icon: "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z",
    color: "text-amber-400",
    children: [
      { href: "/", label: "Dashboard" },
      { href: "/traffic", label: "Traffic" },
      { href: "/nat/flows", label: "NAT Flows" },
      { href: "/connections", label: "Connections" },
      { href: "/blocked", label: "Blocked Traffic" },
      { href: "/threats", label: "Threats" },
      { href: "/logs", label: "Logs" },
    ],
  },

  {
    label: "Firewall",
    icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
    color: "text-blue-400",
    children: [
      { href: "/rules", label: "All Rules" },
      { href: "/aliases", label: "Aliases" },
      { href: "/rules/schedules", label: "Schedules" },
      { href: "/nat/port-forward", label: "Port Forward" },
      { href: "/nat/outbound", label: "Outbound NAT" },
      { href: "/geoip", label: "Geo-IP" },
    ],
    dynamicChildren: true,
  },

  {
    label: "Network",
    icon: "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9",
    color: "text-emerald-400",
    children: [
      { href: "/interfaces", label: "Interfaces" },
      { href: "/vlans", label: "VLANs" },
      { href: "/routes", label: "Routes" },
      { href: "/vpn", label: "VPN" },
    ],
  },

  {
    label: "Services",
    icon: "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2",
    color: "text-purple-400",
    children: [
      { href: "/ca", label: "Certificates" },
      { href: "/dns", label: "DNS Resolver" },
      { href: "/dns/hosts", label: "  Host Overrides" },
      { href: "/dns/forwarding", label: "  Query Forwarding" },
      { href: "/dns/domains", label: "  Domain Overrides" },
      { href: "/dns/acls", label: "  Access Lists" },
      { href: "/dns/logs", label: "  Query Log" },
      { href: "/dhcp", label: "DHCP Server" },
      { href: "/dhcp/subnets", label: "  Subnets" },
      { href: "/dhcp/reservations", label: "  Reservations" },
      { href: "/dhcp/leases", label: "  Leases" },
      { href: "/dhcp/ddns", label: "  Dynamic DNS" },
      { href: "/dhcp/ha", label: "  High Availability" },
      { href: "/dhcp/metrics", label: "  Pool Metrics" },
      { href: "/dhcp/logs", label: "  Logs" },
      { href: "/cluster", label: "Cluster / HA" },
      { href: "/reverse-proxy", label: "Reverse Proxy" },
      { href: "/reverse-proxy/entrypoints", label: "  Entrypoints" },
      { href: "/reverse-proxy/http/routers", label: "  HTTP Routers" },
      { href: "/reverse-proxy/http/services", label: "  HTTP Services" },
      { href: "/reverse-proxy/http/middlewares", label: "  Middlewares" },
      { href: "/reverse-proxy/tcp", label: "  TCP" },
      { href: "/reverse-proxy/udp", label: "  UDP" },
      { href: "/reverse-proxy/tls", label: "  TLS / Certificates" },
      { href: "/reverse-proxy/logs", label: "  Logs" },
    ],
  },

  {
    label: "System",
    icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
    color: "text-gray-400",
    children: [
      { href: "/updates", label: "Updates" },
      { href: "/users", label: "Users" },
      { href: "/backup", label: "Backup & Restore" },
      { href: "/settings", label: "Settings" },
      { href: "/reboot", label: "Reboot" },
    ],
  },
];

export default function Sidebar({ onClose, width }: { onClose?: () => void; width?: number }) {
  const pathname = usePathname();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    Monitoring: true,
    Firewall: true,
    Network: true,
    Services: false,
    System: false,
  });
  const [interfaces, setInterfaces] = useState<{ name: string; role?: string }[]>([]);

  useEffect(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    fetch("/api/v1/interfaces", { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.ok ? r.json() : { data: [] })
      .then((d) => {
        const ifaces = (d.data || [])
          .filter((i: { name: string }) => !i.name.startsWith("lo") && !i.name.startsWith("pflog"))
          .map((i: { name: string; role?: string }) => ({ name: i.name, role: i.role }));
        setInterfaces(ifaces);
      })
      .catch(() => {});
  }, []);

  const toggle = (label: string) => setExpanded((p) => ({ ...p, [label]: !p[label] }));

  const isActive = (href: string) =>
    pathname === href || pathname === href + "/" || (href !== "/" && pathname.startsWith(href + "/"));

  const getChildren = (item: NavItem): NavChild[] => {
    if (!item.children) return [];
    if (!item.dynamicChildren) return item.children;

    const result: NavChild[] = [];
    for (const child of item.children) {
      result.push(child);
      if (child.href === "/rules" && interfaces.length > 0) {
        for (const iface of interfaces) {
          const label = iface.role ? `${iface.name} (${iface.role})` : iface.name;
          result.push({ href: `/rules?interface=${iface.name}`, label });
        }
      }
    }
    return result;
  };

  const hasActiveChild = (children?: NavChild[]) =>
    children?.some((c) => {
      const href = c.href.split("?")[0];
      return isActive(href);
    }) ?? false;

  return (
    <aside className="h-screen bg-[var(--bg-secondary)] border-r border-[var(--border)] flex flex-col" style={{ width: width || 232 }}>
      {/* Logo — links to About page */}
      <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
        <Link href="/about" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h1 className="font-bold text-sm text-[var(--text-primary)] tracking-tight">AiFw</h1>
            <p className="text-[10px] text-[var(--text-muted)]">AI-Powered Firewall</p>
          </div>
        </Link>
        {onClose && (
          <button onClick={onClose} className="lg:hidden text-[var(--text-muted)] hover:text-[var(--text-primary)]">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      <nav className="flex-1 py-2 overflow-y-auto">
        {navItems.map((item, idx) => {
          const hasChildren = !!item.children?.length;

          // Simple link item (Dashboard)
          if (!hasChildren && item.href) {
            const active = isActive(item.href);
            return (
              <Link key={item.href} href={item.href}
                className={`flex items-center gap-3 px-4 py-2 mx-2 my-0.5 rounded-md text-sm transition-colors ${
                  active
                    ? "bg-[var(--accent)] text-white shadow-sm"
                    : "text-[var(--text-secondary)] hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)]"
                }`}>
                <svg className={`w-4 h-4 flex-shrink-0 ${active ? "text-white" : item.color}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                </svg>
                {item.label}
              </Link>
            );
          }

          // Section group
          const isOpen = expanded[item.label] ?? false;
          const children = getChildren(item);
          const childActive = hasActiveChild(children);

          return (
            <div key={item.label}>
              {/* Section divider */}
              {idx > 0 && <div className="mx-4 my-1.5 border-t border-[var(--border)] opacity-50" />}

              <button onClick={() => toggle(item.label)}
                className={`flex items-center gap-2.5 px-4 py-1.5 mx-2 my-0.5 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors w-[calc(100%-16px)] ${
                  childActive ? "text-[var(--text-primary)]" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                }`}>
                <svg className={`w-3.5 h-3.5 flex-shrink-0 ${item.color}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                </svg>
                <span className="flex-1 text-left">{item.label}</span>
                <svg className={`w-3 h-3 flex-shrink-0 transition-transform duration-200 ${isOpen ? "rotate-90" : ""}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
              </button>
              {isOpen && children.length > 0 && (
                <div className="ml-2">
                  {children.map((child) => {
                    const isNicLink = child.href.includes("?interface=");
                    const nicName = isNicLink ? child.href.split("?interface=")[1] : null;
                    const active = isNicLink
                      ? pathname === "/rules" && typeof window !== "undefined" && window.location.search === `?interface=${nicName}`
                      : isActive(child.href);
                    const isSubItem = child.label.startsWith("  ");
                    const displayLabel = child.label.trimStart();
                    return (
                      <Link key={child.href} href={child.href}
                        className={`flex items-center gap-2 ${isNicLink ? "pl-11" : isSubItem ? "pl-12" : "pl-8"} pr-4 py-1.5 mx-2 my-px rounded-md ${isNicLink || isSubItem ? "text-xs" : "text-sm"} transition-colors ${
                          active
                            ? "bg-[var(--accent)]/15 text-[var(--accent)] border-l-2 border-[var(--accent)] -ml-0"
                            : "text-[var(--text-secondary)] hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)]"
                        }`}>
                        {isNicLink ? (
                          <span className={`text-[10px] ${active ? "text-[var(--accent)]" : "text-cyan-400"}`}>&#x2B22;</span>
                        ) : (
                          <span className={`w-1 h-1 rounded-full flex-shrink-0 ${active ? "bg-[var(--accent)]" : "bg-current opacity-30"}`} />
                        )}
                        {displayLabel}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      <div className="p-2 border-t border-[var(--border)] space-y-1">
        <Link href="/profile"
          className={`flex items-center gap-2 px-2 py-1.5 rounded-md text-xs transition-colors ${
            pathname === "/profile" || pathname === "/profile/"
              ? "bg-[var(--accent)]/15 text-[var(--accent)]"
              : "text-[var(--text-secondary)] hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)]"
          }`}>
          <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
          </svg>
          My Profile
        </Link>
        <button
          onClick={() => { localStorage.removeItem("aifw_token"); window.location.href = "/login"; }}
          className="flex items-center gap-2 px-2 py-1.5 rounded-md text-xs text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors w-full">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
          </svg>
          Logout
        </button>
      </div>
    </aside>
  );
}
