"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";

interface NavChild { href: string; label: string; }
interface NavItem {
  href?: string;
  label: string;
  icon: string;
  children?: NavChild[];
  dynamicChildren?: boolean; // marker for dynamic NIC children under Rules
}

const navItems: NavItem[] = [
  { href: "/", label: "Dashboard", icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0h4" },

  // Firewall group
  {
    label: "Firewall",
    icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2",
    children: [
      { href: "/rules", label: "All Rules" },
      // NIC-specific rules injected dynamically below
      { href: "/rules/schedules", label: "Schedules" },
      { href: "/nat/port-forward", label: "Port Forward" },
      { href: "/nat/outbound", label: "Outbound NAT" },
      { href: "/geoip", label: "Geo-IP" },
    ],
    dynamicChildren: true,
  },

  // Network group
  {
    label: "Network",
    icon: "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9",
    children: [
      { href: "/connections", label: "Connections" },
      { href: "/traffic", label: "Traffic" },
      { href: "/interfaces", label: "Interfaces" },
      { href: "/vlans", label: "VLANs" },
      { href: "/routes", label: "Routes" },
      { href: "/vpn", label: "VPN" },
    ],
  },

  // Services group
  {
    label: "Services",
    icon: "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2",
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
      { href: "/dhcp/logs", label: "  Logs" },
      { href: "/cluster", label: "Cluster / HA" },
    ],
  },

  // Monitoring group
  {
    label: "Monitoring",
    icon: "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z",
    children: [
      { href: "/threats", label: "Threats" },
      { href: "/logs", label: "Logs" },
    ],
  },

  // System group
  {
    label: "System",
    icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
    children: [
      { href: "/updates", label: "Updates" },
      { href: "/users", label: "Users" },
      { href: "/backup", label: "Backup & Restore" },
      { href: "/settings", label: "Settings" },
    ],
  },
];

export default function Sidebar({ onClose, width }: { onClose?: () => void; width?: number }) {
  const pathname = usePathname();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    Firewall: true,
    Network: true,
    Services: false,
    Monitoring: false,
    System: false,
  });
  const [interfaces, setInterfaces] = useState<string[]>([]);

  useEffect(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    fetch("/api/v1/interfaces", { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.ok ? r.json() : { data: [] })
      .then((d) => {
        const names = (d.data || [])
          .map((i: { name: string }) => i.name)
          .filter((n: string) => !n.startsWith("lo") && !n.startsWith("pflog"));
        setInterfaces(names);
      })
      .catch(() => {});
  }, []);

  const toggle = (label: string) => setExpanded((p) => ({ ...p, [label]: !p[label] }));

  const isActive = (href: string) =>
    pathname === href || pathname === href + "/" || (href !== "/" && pathname.startsWith(href + "/"));

  // Build children with dynamic NIC entries injected
  const getChildren = (item: NavItem): NavChild[] => {
    if (!item.children) return [];
    if (!item.dynamicChildren) return item.children;

    // Inject NIC-specific rule links after "All Rules"
    const result: NavChild[] = [];
    for (const child of item.children) {
      result.push(child);
      if (child.href === "/rules" && interfaces.length > 0) {
        for (const nic of interfaces) {
          result.push({ href: `/rules?interface=${nic}`, label: nic });
        }
      }
    }
    return result;
  };

  const hasActiveChild = (children?: NavChild[]) =>
    children?.some((c) => {
      const href = c.href.split("?")[0]; // strip query params for matching
      return isActive(href);
    }) ?? false;

  return (
    <aside className="h-screen bg-[var(--bg-secondary)] border-r border-[var(--border)] flex flex-col" style={{ width: width || 224 }}>
      <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-[var(--accent)] flex items-center justify-center font-bold text-white text-sm">
            AI
          </div>
          <div>
            <h1 className="font-bold text-sm text-[var(--text-primary)]">AiFw</h1>
            <p className="text-[10px] text-[var(--text-muted)]">AI Firewall</p>
          </div>
        </div>
        {onClose && (
          <button onClick={onClose} className="lg:hidden text-[var(--text-muted)] hover:text-[var(--text-primary)]">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      <nav className="flex-1 py-2 overflow-y-auto">
        {navItems.map((item) => {
          const hasChildren = !!item.children?.length;

          // Simple link item (Dashboard)
          if (!hasChildren && item.href) {
            const active = isActive(item.href);
            return (
              <Link key={item.href} href={item.href}
                className={`flex items-center gap-3 px-4 py-2 mx-2 my-0.5 rounded-md text-sm transition-colors ${
                  active ? "bg-[var(--accent)] text-white" : "text-[var(--text-secondary)] hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)]"
                }`}>
                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                </svg>
                {item.label}
              </Link>
            );
          }

          // Tree group
          const isOpen = expanded[item.label] ?? false;
          const children = getChildren(item);
          const childActive = hasActiveChild(children);

          return (
            <div key={item.label}>
              <button onClick={() => toggle(item.label)}
                className={`flex items-center gap-3 px-4 py-1.5 mx-2 my-0.5 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors w-[calc(100%-16px)] ${
                  childActive ? "text-[var(--text-primary)]" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                }`}>
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
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
                          active ? "bg-[var(--accent)] text-white" : "text-[var(--text-secondary)] hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)]"
                        }`}>
                        {isNicLink ? (
                          <span className={`text-[10px] ${active ? "text-white" : "text-cyan-400"}`}>⬡</span>
                        ) : (
                          <span className={`w-1 h-1 rounded-full flex-shrink-0 ${active ? "bg-white" : "bg-current opacity-40"}`} />
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
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)]"
          }`}>
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
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
        <div className="text-[10px] text-[var(--text-muted)] px-2 pt-1">v5.2.0 &middot; MIT</div>
      </div>
    </aside>
  );
}
