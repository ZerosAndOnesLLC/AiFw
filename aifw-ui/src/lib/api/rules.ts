import { api, Rule, Schedule, UpdateRuleRequest } from "@/lib/api";
import { validateAddress, validatePort } from "@/lib/validate";

/* ─── Shared API types re-exported for the rules page ───────────── */

export type {
  Rule,
  CreateRuleRequest,
  UpdateRuleRequest,
  InterfaceInfo,
  Schedule,
} from "@/lib/api";

/* ─── Subnet masks ──────────────────────────────────────────────── */

export const SUBNET_MASKS = [
  "/32", "/31", "/30", "/29", "/28", "/27", "/26", "/25",
  "/24", "/23", "/22", "/21", "/20", "/19", "/18", "/17",
  "/16", "/15", "/14", "/13", "/12", "/11", "/10", "/9", "/8",
  "/7", "/6", "/5", "/4", "/3", "/2", "/1", "/0",
];

/* ─── Form state ─────────────────────────────────────────────────── */

export interface RuleForm {
  action: string;
  disabled: boolean;
  interface: string;
  direction: string;
  ip_version: string;
  protocol: string;
  src_type: "any" | "address";
  src_addr: string;
  src_mask: string;
  src_invert: boolean;
  src_port: string;
  dst_type: "any" | "address";
  dst_addr: string;
  dst_mask: string;
  dst_invert: boolean;
  dst_port: string;
  log: boolean;
  description: string;
  gateway: string;
  state_tracking: string;
  label: string;
  schedule_id: string;
}

export const defaultForm: RuleForm = {
  action: "pass",
  disabled: false,
  interface: "any",
  direction: "in",
  ip_version: "both",
  protocol: "tcp",
  src_type: "any",
  src_addr: "",
  src_mask: "/32",
  src_invert: false,
  src_port: "",
  dst_type: "any",
  dst_addr: "",
  dst_mask: "/32",
  dst_invert: false,
  dst_port: "",
  log: false,
  description: "",
  gateway: "",
  state_tracking: "keep_state",
  label: "",
  schedule_id: "",
};

export const PROTOCOLS = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "tcp/udp", label: "TCP/UDP" },
  { value: "icmp", label: "ICMP" },
  { value: "icmp6", label: "ICMPv6" },
  { value: "esp", label: "ESP" },
  { value: "ah", label: "AH" },
  { value: "gre", label: "GRE" },
  { value: "any", label: "Any" },
];

export const ACTIONS = [
  { value: "pass", label: "Pass" },
  { value: "block", label: "Block" },
  { value: "block_drop", label: "Block (drop)" },
  { value: "block_return", label: "Block (return)" },
];

export const IP_VERSIONS = [
  { value: "inet", label: "IPv4" },
  { value: "inet6", label: "IPv6" },
  { value: "both", label: "IPv4+IPv6" },
];

export const STATE_TYPES = [
  { value: "keep_state", label: "Keep state" },
  { value: "modulate_state", label: "Modulate state" },
  { value: "synproxy_state", label: "Synproxy state" },
  { value: "none", label: "None" },
];

export function protocolShowsPorts(proto: string): boolean {
  return proto === "tcp" || proto === "udp" || proto === "tcp/udp";
}

/** Split "192.168.1.0/24" into ["192.168.1.0", "/24"] */
function splitCidr(addr: string): { ip: string; mask: string } {
  if (!addr || addr === "any") return { ip: "", mask: "/32" };
  const idx = addr.indexOf("/");
  if (idx === -1) return { ip: addr, mask: "/32" };
  return { ip: addr.substring(0, idx), mask: addr.substring(idx) };
}

/* ─── Formatting helpers ─────────────────────────────────────────── */

function formatPort(port: { start: number; end: number } | null | undefined): string {
  if (!port) return "*";
  if (port.start === port.end) return String(port.start);
  return `${port.start}-${port.end}`;
}

export function formatAddrPort(
  addr: string,
  port: { start: number; end: number } | null | undefined,
  invert?: boolean,
): string {
  const prefix = invert ? "! " : "";
  const portStr = port ? `:${formatPort(port)}` : "";
  return `${prefix}${addr}${portStr}`;
}

export function ipVersionLabel(v?: string): string {
  if (v === "inet6") return "IPv6";
  if (v === "inet") return "IPv4";
  return "IPv4+6"; // "both" (and legacy "inet46")
}

export function actionLabel(a: string): string {
  if (a === "block_drop") return "block";
  if (a === "block_return") return "block";
  return a;
}

export function getScheduleName(schedules: Schedule[], scheduleId?: string): string | null {
  if (!scheduleId) return null;
  const sched = schedules.find((s) => s.id === scheduleId);
  return sched ? sched.name : null;
}

/* ─── Client-side validation ─────────────────────────────────────── */

export function validateRuleForm(form: RuleForm): string[] {
  const errors: string[] = [];
  if (form.src_type === "address" && form.src_addr) {
    const e = validateAddress(`${form.src_addr}${form.src_mask}`, "Source address");
    if (e) errors.push(e);
  }
  if (form.dst_type === "address" && form.dst_addr) {
    const e = validateAddress(`${form.dst_addr}${form.dst_mask}`, "Destination address");
    if (e) errors.push(e);
  }
  if (form.src_port) {
    const e = validatePort(form.src_port, "Source port");
    if (e) errors.push(e);
  }
  if (form.dst_port) {
    const e = validatePort(form.dst_port, "Destination port");
    if (e) errors.push(e);
  }
  return errors;
}

/* ─── Form ⇄ API mapping ─────────────────────────────────────────── */

/** Build the create/update request body from the form state. */
export function buildRuleBody(form: RuleForm): UpdateRuleRequest {
  const srcAddr = form.src_type === "any" || !form.src_addr || form.src_addr.toLowerCase() === "any"
    ? "any" : `${form.src_addr}${form.src_mask}`;
  const dstAddr = form.dst_type === "any" || !form.dst_addr || form.dst_addr.toLowerCase() === "any"
    ? "any" : `${form.dst_addr}${form.dst_mask}`;
  const showPorts = protocolShowsPorts(form.protocol);

  return {
    action: form.action,
    direction: form.direction,
    protocol: form.protocol,
    ip_version: form.ip_version,
    interface: form.interface === "any" ? undefined : form.interface,
    src_addr: srcAddr,
    src_port_start: showPorts && form.src_port ? parseInt(form.src_port, 10) : null,
    src_invert: form.src_invert,
    dst_addr: dstAddr,
    dst_port_start: showPorts && form.dst_port ? parseInt(form.dst_port, 10) : null,
    dst_invert: form.dst_invert,
    log: form.log,
    quick: true,
    label: form.label || undefined,
    description: form.description || undefined,
    gateway: form.gateway || null,
    schedule_id: form.schedule_id || null,
    state_tracking: form.state_tracking,
    status: form.disabled ? "disabled" : "active",
  };
}

/** Map an existing rule back into form state (for edit/clone). */
export function ruleToForm(rule: Rule): RuleForm {
  const srcIsAny = !rule.rule_match.src_addr || rule.rule_match.src_addr.toLowerCase() === "any";
  const dstIsAny = !rule.rule_match.dst_addr || rule.rule_match.dst_addr.toLowerCase() === "any";
  const srcParts = splitCidr(rule.rule_match.src_addr);
  const dstParts = splitCidr(rule.rule_match.dst_addr);

  return {
    action: rule.action,
    disabled: rule.status === "disabled",
    interface: rule.interface || "any",
    direction: rule.direction,
    ip_version: rule.ip_version || "both",
    protocol: rule.protocol,
    src_type: srcIsAny ? "any" : "address",
    src_addr: srcIsAny ? "" : srcParts.ip,
    src_mask: srcIsAny ? "/32" : srcParts.mask,
    src_invert: rule.rule_match.src_invert || false,
    src_port: rule.rule_match.src_port ? String(rule.rule_match.src_port.start) : "",
    dst_type: dstIsAny ? "any" : "address",
    dst_addr: dstIsAny ? "" : dstParts.ip,
    dst_mask: dstIsAny ? "/32" : dstParts.mask,
    dst_invert: rule.rule_match.dst_invert || false,
    dst_port: rule.rule_match.dst_port ? String(rule.rule_match.dst_port.start) : "",
    log: rule.log,
    description: rule.description || "",
    gateway: rule.gateway || "",
    state_tracking: rule.state_options.tracking,
    label: rule.label || "",
    schedule_id: rule.schedule_id || "",
  };
}

/** Build the update body that flips a rule between active/disabled. */
export function toggleStatusRequest(rule: Rule): UpdateRuleRequest {
  const newStatus = rule.status === "active" ? "disabled" : "active";
  return {
    action: rule.action,
    direction: rule.direction,
    protocol: rule.protocol,
    ip_version: rule.ip_version || "both",
    interface: rule.interface || undefined,
    src_addr: rule.rule_match.src_addr,
    src_port_start: rule.rule_match.src_port ? rule.rule_match.src_port.start : null,
    src_invert: rule.rule_match.src_invert || false,
    dst_addr: rule.rule_match.dst_addr,
    dst_port_start: rule.rule_match.dst_port ? rule.rule_match.dst_port.start : null,
    dst_invert: rule.rule_match.dst_invert || false,
    log: rule.log,
    label: rule.label || undefined,
    description: rule.description || undefined,
    gateway: rule.gateway || null,
    schedule_id: rule.schedule_id || null,
    state_tracking: rule.state_options.tracking,
    status: newStatus,
  };
}

/* ─── Rule API calls not covered by named api.* methods ──────────── */

/** Persist a new global rule order. */
export function reorderRules(ruleIds: string[]) {
  return api.put("/api/v1/rules/reorder", { rule_ids: ruleIds });
}

/** Toggle logging on all block rules (performance testing). */
export function postBlockLogging(enabled: boolean) {
  return api.post("/api/v1/rules/block-logging", { enabled });
}
