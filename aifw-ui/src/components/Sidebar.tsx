"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import { useAuth } from "@/context/AuthContext";

interface NavChild { href: string; label: string; permission?: string; }
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
      { href: "/", label: "Dashboard", permission: "dashboard:view" },
      { href: "/traffic", label: "Traffic", permission: "dashboard:view" },
      { href: "/nat/flows", label: "NAT Flows", permission: "nat:read" },
      { href: "/connections", label: "Connections", permission: "connections:view" },
      { href: "/blocked", label: "Blocked Traffic", permission: "connections:view" },
      { href: "/threats", label: "Threats", permission: "ids:read" },
      { href: "/logs", label: "Logs", permission: "logs:view" },
    ],
  },

  {
    label: "Firewall",
    icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
    color: "text-blue-400",
    children: [
      { href: "/rules", label: "All Rules", permission: "rules:read" },
      { href: "/aliases", label: "Aliases", permission: "aliases:read" },
      { href: "/rules/schedules", label: "Schedules", permission: "rules:read" },
      { href: "/nat/port-forward", label: "Port Forward", permission: "nat:read" },
      { href: "/nat/outbound", label: "Outbound NAT", permission: "nat:read" },
      { href: "/geoip", label: "Geo-IP", permission: "geoip:read" },
    ],
    dynamicChildren: true,
  },

  {
    label: "Network",
    icon: "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9",
    color: "text-emerald-400",
    children: [
      { href: "/interfaces", label: "Interfaces", permission: "interfaces:read" },
      { href: "/vlans", label: "VLANs", permission: "interfaces:read" },
      { href: "/routes", label: "Routes", permission: "interfaces:read" },
      { href: "/vpn", label: "VPN", permission: "vpn:read" },
    ],
  },

  {
    label: "Services",
    icon: "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2",
    color: "text-purple-400",
    children: [
      { href: "/ca", label: "Certificates", permission: "settings:read" },
      { href: "/dns", label: "DNS Resolver", permission: "dns:read" },
      { href: "/dns/hosts", label: "  Host Overrides", permission: "dns:read" },
      { href: "/dns/forwarding", label: "  Query Forwarding", permission: "dns:read" },
      { href: "/dns/domains", label: "  Domain Overrides", permission: "dns:read" },
      { href: "/dns/acls", label: "  Access Lists", permission: "dns:read" },
      { href: "/dns/logs", label: "  Query Log", permission: "dns:read" },
      { href: "/dhcp", label: "DHCP Server", permission: "dhcp:read" },
      { href: "/dhcp/subnets", label: "  Subnets", permission: "dhcp:read" },
      { href: "/dhcp/reservations", label: "  Reservations", permission: "dhcp:read" },
      { href: "/dhcp/leases", label: "  Leases", permission: "dhcp:read" },
      { href: "/dhcp/ddns", label: "  Dynamic DNS", permission: "dhcp:read" },
      { href: "/dhcp/ha", label: "  High Availability", permission: "dhcp:read" },
      { href: "/dhcp/metrics", label: "  Pool Metrics", permission: "dhcp:read" },
      { href: "/dhcp/logs", label: "  Logs", permission: "dhcp:read" },
      { href: "/cluster", label: "Cluster / HA", permission: "settings:read" },
      { href: "/reverse-proxy", label: "Reverse Proxy", permission: "proxy:read" },
      { href: "/reverse-proxy/entrypoints", label: "  Entrypoints", permission: "proxy:read" },
      { href: "/reverse-proxy/http/routers", label: "  HTTP Routers", permission: "proxy:read" },
      { href: "/reverse-proxy/http/services", label: "  HTTP Services", permission: "proxy:read" },
      { href: "/reverse-proxy/http/middlewares", label: "  Middlewares", permission: "proxy:read" },
      { href: "/reverse-proxy/tcp", label: "  TCP", permission: "proxy:read" },
      { href: "/reverse-proxy/udp", label: "  UDP", permission: "proxy:read" },
      { href: "/reverse-proxy/tls", label: "  TLS / Certificates", permission: "proxy:read" },
      { href: "/reverse-proxy/logs", label: "  Logs", permission: "proxy:read" },
      { href: "/time", label: "Time (NTP/PTP)", permission: "settings:read" },
      { href: "/time/logs", label: "  Logs", permission: "settings:read" },
    ],
  },

  {
    label: "Intrusion Detection",
    icon: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z",
    color: "text-red-400",
    children: [
      { href: "/ids", label: "Dashboard", permission: "ids:read" },
      { href: "/ids/alerts", label: "Alerts", permission: "ids:read" },
      { href: "/ids/rules", label: "Rules", permission: "ids:read" },
      { href: "/ids/rulesets", label: "Rulesets", permission: "ids:read" },
      { href: "/ids/settings", label: "Settings", permission: "ids:read" },
    ],
  },

  {
    label: "Extensions",
    icon: "M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4",
    color: "text-indigo-400",
    children: [
      { href: "/plugins", label: "Plugins", permission: "plugins:read" },
    ],
  },

  {
    label: "System",
    icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
    color: "text-gray-400",
    children: [
      { href: "/updates", label: "Updates", permission: "updates:read" },
      { href: "/users", label: "Users", permission: "users:read" },
      { href: "/backup", label: "Backup & Restore", permission: "backup:read" },
      { href: "/settings", label: "Settings", permission: "settings:read" },
      { href: "/reboot", label: "Reboot", permission: "system:reboot" },
    ],
  },
];

export default function Sidebar({ onClose, width }: { onClose?: () => void; width?: number }) {
  const pathname = usePathname();
  const { permissions, isLoading: authLoading } = useAuth();
  // If auth hasn't loaded yet or user has no permissions in JWT (legacy token),
  // show all nav items instead of hiding everything
  const permLoaded = !authLoading && permissions.size > 0;
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    Monitoring: true,
    Firewall: false,
    Network: false,
    Services: false,
    "Intrusion Detection": false,
    Extensions: false,
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

    // Filter by permission — hide items user can't access.
    // If permissions haven't loaded yet, show everything.
    const filtered = !permLoaded
      ? item.children
      : item.children.filter((c) => !c.permission || permissions.has(c.permission));

    if (!item.dynamicChildren) return filtered;

    const result: NavChild[] = [];
    for (const child of filtered) {
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
      <div className="border-b border-[var(--border)] flex items-center justify-between bg-gradient-to-b from-black via-black/90 to-transparent">
        <Link href="/about" className="flex-1 flex items-center justify-center py-3 hover:opacity-90 transition-opacity">
          <img src="/logo-sidebar.png" alt="AiFw" className="w-full max-h-28 object-contain px-2" />
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
          // Hide entire section if all children are filtered out by permissions
          if (children.length === 0) return null;
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
                          <span className={`w-1 h-1 rounded-full flex-shrink-0 ${active ? "bg-[var(--accent)]" : "bg-current opacity-50"}`} />
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
