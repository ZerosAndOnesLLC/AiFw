// Typed API layer for the Multi-WAN policy-routing page (#428 / QUAL-H8).
// All HTTP calls and page-level resource types live here — no React.
//
// Resource types shared across the multi-wan pages (Gateway, GatewayGroup,
// PolicyRule, RoutingInstance) remain defined in `@/app/multi-wan/lib` —
// other pages still import them from there — and are re-exported here so
// the policies page's hook/components have a single import surface.

import { api } from "@/lib/api";
import {
  Gateway,
  GatewayGroup,
  PolicyRule,
  RoutingInstance,
  validateCidr,
  validateInterface,
  validateName,
  validatePortSpec,
} from "@/app/multi-wan/lib";

export type { Gateway, GatewayGroup, PolicyRule, RoutingInstance };

/* ────────────────────────── Types ────────────────────────── */

export interface BlastRadius {
  would_strand_mgmt: boolean;
  new_rules: string[];
  removed_rules: string[];
  affected_flows: Array<{
    src: string;
    dst: string;
    protocol: string;
    current_iface: string | null;
    bytes: number;
  }>;
  validation: { severity: string; message: string }[];
}

export interface FormState {
  priority: number;
  name: string;
  status: string;
  ip_version: string;
  iface_in: string;
  src_addr: string;
  dst_addr: string;
  src_port: string;
  dst_port: string;
  protocol: string;
  action_kind: string;
  target_id: string;
  description: string;
}

export const defaultForm: FormState = {
  priority: 100,
  name: "",
  status: "active",
  ip_version: "both",
  iface_in: "",
  src_addr: "any",
  dst_addr: "any",
  src_port: "",
  dst_port: "",
  protocol: "any",
  action_kind: "set_gateway",
  target_id: "",
  description: "",
};

/// Request body for create/update policy.
export interface PolicyRuleBody {
  priority: number;
  name: string;
  status: string;
  ip_version: string;
  iface_in: string | null;
  src_addr: string;
  dst_addr: string;
  src_port: string | null;
  dst_port: string | null;
  protocol: string;
  action_kind: string;
  target_id: string;
  description: string | null;
}

/* ────────────────────────── Presets ────────────────────────── */

export interface Preset {
  name: string;
  icon: string;
  description: string;
  apply: (form: FormState) => FormState;
}

export const PRESETS: Preset[] = [
  {
    name: "Streaming via WAN2",
    icon: "🎬",
    description: "Route Netflix/YouTube/Twitch (TCP 443) via a specific gateway",
    apply: (f) => ({
      ...f,
      name: "streaming-wan2",
      protocol: "tcp",
      dst_port: "443",
      action_kind: "set_gateway",
      description: "Offload streaming to secondary WAN",
    }),
  },
  {
    name: "VoIP on primary",
    icon: "📞",
    description: "Pin SIP/RTP to best-quality gateway group",
    apply: (f) => ({
      ...f,
      name: "voip-primary",
      protocol: "udp",
      dst_port: "5060,10000:20000",
      action_kind: "set_group",
      description: "VoIP routed through lowest-jitter WAN",
    }),
  },
  {
    name: "Work LAN → VPN",
    icon: "🔐",
    description: "Route 10.10.0.0/24 through a secondary routing instance",
    apply: (f) => ({
      ...f,
      name: "work-lan-vpn",
      src_addr: "10.10.0.0/24",
      action_kind: "set_instance",
      description: "Isolate work VLAN on dedicated FIB",
    }),
  },
  {
    name: "DNS → primary",
    icon: "🌐",
    description: "Force DNS (UDP/53) out the primary WAN only",
    apply: (f) => ({
      ...f,
      name: "dns-primary",
      protocol: "udp",
      dst_port: "53",
      action_kind: "set_gateway",
      description: "Predictable DNS resolution path",
    }),
  },
];

/* ────────────────────────── HTTP calls ────────────────────────── */

export async function listPolicies(): Promise<PolicyRule[]> {
  const res = await api.get<{ data: PolicyRule[] }>("/api/v1/multiwan/policies");
  return res.data;
}

export async function listInstances(): Promise<RoutingInstance[]> {
  const res = await api.get<{ data: RoutingInstance[] }>("/api/v1/multiwan/instances");
  return res.data;
}

export async function listGateways(): Promise<Gateway[]> {
  const res = await api.get<{ data: Gateway[] }>("/api/v1/multiwan/gateways");
  return res.data;
}

export async function listGroups(): Promise<GatewayGroup[]> {
  const res = await api.get<{ data: GatewayGroup[] }>("/api/v1/multiwan/groups");
  return res.data;
}

export async function createPolicy(body: PolicyRuleBody): Promise<void> {
  await api.post<unknown>("/api/v1/multiwan/policies", body);
}

export async function updatePolicy(id: string, body: PolicyRuleBody): Promise<void> {
  await api.put<unknown>(`/api/v1/multiwan/policies/${id}`, body);
}

export async function deletePolicy(id: string): Promise<void> {
  await api.delete<unknown>(`/api/v1/multiwan/policies/${id}`);
}

export async function togglePolicy(id: string, enabled: boolean): Promise<void> {
  await api.put<unknown>(`/api/v1/multiwan/policies/${id}/toggle`, { enabled });
}

export async function duplicatePolicy(id: string): Promise<void> {
  await api.post<unknown>(`/api/v1/multiwan/policies/${id}/duplicate`);
}

export async function applyPolicies(): Promise<void> {
  await api.post<unknown>("/api/v1/multiwan/apply", {});
}

export async function reorderPolicies(policyIds: string[]): Promise<void> {
  await api.put<unknown>("/api/v1/multiwan/policies/reorder", {
    policy_ids: policyIds,
  });
}

export async function previewBlastRadius(policies: PolicyRule[]): Promise<BlastRadius> {
  const report = await api.post<{ data: BlastRadius }>("/api/v1/multiwan/preview", {
    policies: policies.map((p) => ({
      priority: p.priority,
      name: p.name,
      status: p.status,
      ip_version: p.ip_version,
      iface_in: p.iface_in,
      src_addr: p.src_addr,
      dst_addr: p.dst_addr,
      src_port: p.src_port,
      dst_port: p.dst_port,
      protocol: p.protocol,
      action_kind: p.action_kind,
      target_id: p.target_id,
      description: p.description,
    })),
  });
  return report.data;
}

/* ────────────────────────── Pure helpers ────────────────────────── */

/// Build the create/update request body from the form.
export function policyBodyFromForm(form: FormState): PolicyRuleBody {
  return {
    priority: form.priority,
    name: form.name,
    status: form.status,
    ip_version: form.ip_version,
    iface_in: form.iface_in || null,
    src_addr: form.src_addr,
    dst_addr: form.dst_addr,
    src_port: form.src_port || null,
    dst_port: form.dst_port || null,
    protocol: form.protocol,
    action_kind: form.action_kind,
    target_id: form.target_id,
    description: form.description || null,
  };
}

/// Field-level validation. Returns a map of field → error message;
/// empty map means the form is valid.
export function validatePolicyForm(form: FormState): Record<string, string> {
  const e: Record<string, string> = {};
  if (form.priority < 1 || form.priority > 65535) e.priority = "1–65535";
  const n = validateName(form.name);
  if (n) e.name = n;
  if (form.iface_in) {
    const i = validateInterface(form.iface_in);
    if (i) e.iface_in = i;
  }
  const s = validateCidr(form.src_addr);
  if (s) e.src_addr = s;
  const d = validateCidr(form.dst_addr);
  if (d) e.dst_addr = d;
  const sp = validatePortSpec(form.src_port);
  if (sp) e.src_port = sp;
  const dp = validatePortSpec(form.dst_port);
  if (dp) e.dst_port = dp;
  if (!form.target_id) e.target_id = "required";
  if (form.dst_port && form.protocol === "any")
    e.protocol = "must be tcp or udp to match ports";
  return e;
}

export interface TargetOption {
  value: string;
  label: string;
  state?: string;
}

/// Options for the "Target" select, keyed off the chosen action kind.
export function targetOptions(
  actionKind: string,
  instances: RoutingInstance[],
  gateways: Gateway[],
  groups: GatewayGroup[],
): TargetOption[] {
  switch (actionKind) {
    case "set_instance":
      return instances.map((i) => ({
        value: i.id,
        label: `${i.name} (FIB ${i.fib_number})`,
      }));
    case "set_gateway":
      return gateways.map((g) => ({
        value: g.id,
        label: `${g.name} (${g.interface} → ${g.next_hop})`,
        state: g.state,
      }));
    case "set_group":
      return groups.map((g) => ({
        value: g.id,
        label: `${g.name} (${g.policy})`,
      }));
    default:
      return [];
  }
}

export interface PolicyTargetLabel {
  text: string;
  color: string;
  health?: string;
}

/// Human-readable target column for a policy row.
export function targetLabel(
  p: PolicyRule,
  instances: RoutingInstance[],
  gateways: Gateway[],
  groups: GatewayGroup[],
): PolicyTargetLabel {
  if (p.action_kind === "set_instance") {
    const i = instances.find((x) => x.id === p.target_id);
    return {
      text: i ? `FIB ${i.fib_number} · ${i.name}` : "?",
      color: "text-cyan-400",
    };
  }
  if (p.action_kind === "set_gateway") {
    const g = gateways.find((x) => x.id === p.target_id);
    return {
      text: g ? g.name : "?",
      color: "text-green-400",
      health: g?.state,
    };
  }
  const g = groups.find((x) => x.id === p.target_id);
  return {
    text: g ? `${g.name} (${g.policy})` : "?",
    color: "text-purple-400",
  };
}

/* ────────────────────────── Live pf preview ────────────────────────── */

export function pfPreview(
  form: FormState,
  instances: RoutingInstance[],
  gateways: Gateway[],
  groups: GatewayGroup[],
): string {
  if (!form.target_id) return "# select a target to preview emitted pf rule";
  const af = form.ip_version === "v4" ? " inet" : form.ip_version === "v6" ? " inet6" : "";
  const proto = form.protocol !== "any" ? ` proto ${form.protocol}` : "";
  const sport = form.src_port ? ` port ${form.src_port}` : "";
  const dport = form.dst_port ? ` port ${form.dst_port}` : "";
  const label = `pbr:<uuid>`;

  if (form.action_kind === "set_instance") {
    const inst = instances.find((i) => i.id === form.target_id);
    if (!inst) return "# instance not found";
    const iface = form.iface_in || "<iface_in>";
    return `pass in quick on ${iface}${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} rtable ${inst.fib_number} keep state (if-bound) label "${label}"`;
  }

  if (form.action_kind === "set_gateway") {
    const gw = gateways.find((g) => g.id === form.target_id);
    if (!gw) return "# gateway not found";
    return [
      `# anchor aifw-pbr`,
      `pass out quick on ${gw.interface}${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} route-to (${gw.interface} ${gw.next_hop}) keep state (if-bound) label "${label}"`,
      ``,
      `# anchor aifw-mwan-reply`,
      `pass in quick${form.iface_in ? ` on ${form.iface_in}` : ""}${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} reply-to (${gw.interface} ${gw.next_hop}) keep state (if-bound) label "${label}:rep"`,
    ].join("\n");
  }

  if (form.action_kind === "set_group") {
    const grp = groups.find((g) => g.id === form.target_id);
    if (!grp) return "# group not found";
    return `# Emitted per currently-healthy members at apply time, e.g.\npass out quick on <iface>${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} route-to { (em1 gw1) weight N, (em2 gw2) weight M } round-robin${
      grp.sticky === "src" ? " sticky-address" : ""
    } keep state (if-bound) label "${label}:grp"`;
  }

  return "";
}
