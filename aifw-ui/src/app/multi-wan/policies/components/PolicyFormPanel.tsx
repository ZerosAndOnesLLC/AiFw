import {
  FormState,
  Gateway,
  GatewayGroup,
  RoutingInstance,
  pfPreview,
  targetOptions,
} from "@/lib/api/multiwan-policies";
import { Field } from "./Field";
import { Section } from "./Section";

function inputCls(hasErr: boolean): string {
  return `w-full px-3 py-2 rounded bg-black/30 border text-white text-sm ${
    hasErr ? "border-red-500" : "border-[var(--border)]"
  }`;
}

/// Slide-over create/edit form. Form state and validation errors are owned
/// by the page; this component only renders them and reports changes.
export function PolicyFormPanel({
  form,
  setForm,
  errs,
  editingId,
  submitting,
  instances,
  gateways,
  groups,
  onSubmit,
  onClose,
}: {
  form: FormState;
  setForm: (form: FormState) => void;
  errs: Record<string, string>;
  editingId: string | null;
  submitting: boolean;
  instances: RoutingInstance[];
  gateways: Gateway[];
  groups: GatewayGroup[];
  onSubmit: (e: React.FormEvent) => void;
  onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-40 bg-black/60 flex items-stretch justify-end"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-[var(--bg-card)] border-l border-[var(--border)] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-[var(--bg-card)] border-b border-[var(--border)] p-4 flex justify-between items-center z-10">
          <h2 className="text-lg font-bold text-white">
            {editingId ? "Edit policy" : "New policy"}
          </h2>
          <button onClick={onClose} className="text-[var(--text-muted)] hover:text-white">
            ✕
          </button>
        </div>

        <form onSubmit={onSubmit} className="p-4 space-y-5">
          <Section title="Identity">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Name" err={errs.name} required>
                <input
                  autoFocus
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className={inputCls(!!errs.name)}
                />
              </Field>
              <Field label="Priority" err={errs.priority} required>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={form.priority}
                  onChange={(e) =>
                    setForm({ ...form, priority: parseInt(e.target.value, 10) || 0 })
                  }
                  className={inputCls(!!errs.priority)}
                />
              </Field>
            </div>
            <Field label="Description">
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className={inputCls(false)}
              />
            </Field>
            <label className="flex items-center gap-2 text-sm text-white">
              <input
                type="checkbox"
                checked={form.status === "active"}
                onChange={(e) =>
                  setForm({ ...form, status: e.target.checked ? "active" : "disabled" })
                }
              />
              Enabled
            </label>
          </Section>

          <Section title="Match">
            <div className="grid grid-cols-2 gap-3">
              <Field label="IP version">
                <select
                  value={form.ip_version}
                  onChange={(e) => setForm({ ...form, ip_version: e.target.value })}
                  className={inputCls(false)}
                >
                  <option value="both">IPv4 + IPv6</option>
                  <option value="v4">IPv4</option>
                  <option value="v6">IPv6</option>
                </select>
              </Field>
              <Field label="Protocol" err={errs.protocol}>
                <select
                  value={form.protocol}
                  onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                  className={inputCls(!!errs.protocol)}
                >
                  <option value="any">any</option>
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                  <option value="icmp">icmp</option>
                </select>
              </Field>
              <Field label="Inbound interface (optional)" err={errs.iface_in}>
                <input
                  value={form.iface_in}
                  onChange={(e) => setForm({ ...form, iface_in: e.target.value })}
                  placeholder="em_lan"
                  className={inputCls(!!errs.iface_in)}
                />
              </Field>
              <div />
              <Field label="Source address" err={errs.src_addr} required>
                <input
                  value={form.src_addr}
                  onChange={(e) => setForm({ ...form, src_addr: e.target.value })}
                  placeholder="10.0.0.0/24 or any"
                  className={inputCls(!!errs.src_addr)}
                />
              </Field>
              <Field label="Destination address" err={errs.dst_addr} required>
                <input
                  value={form.dst_addr}
                  onChange={(e) => setForm({ ...form, dst_addr: e.target.value })}
                  placeholder="any"
                  className={inputCls(!!errs.dst_addr)}
                />
              </Field>
              <Field label="Source port (optional)" err={errs.src_port}>
                <input
                  value={form.src_port}
                  onChange={(e) => setForm({ ...form, src_port: e.target.value })}
                  placeholder="any or 1024:65535"
                  className={inputCls(!!errs.src_port)}
                />
              </Field>
              <Field label="Destination port (optional)" err={errs.dst_port}>
                <input
                  value={form.dst_port}
                  onChange={(e) => setForm({ ...form, dst_port: e.target.value })}
                  placeholder="443 or 80,443"
                  className={inputCls(!!errs.dst_port)}
                />
              </Field>
            </div>
          </Section>

          <Section title="Action">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Action">
                <select
                  value={form.action_kind}
                  onChange={(e) =>
                    setForm({ ...form, action_kind: e.target.value, target_id: "" })
                  }
                  className={inputCls(false)}
                >
                  <option value="set_instance">Set routing instance</option>
                  <option value="set_gateway">Route via gateway</option>
                  <option value="set_group">Route via gateway group</option>
                </select>
              </Field>
              <Field label="Target" err={errs.target_id} required>
                <select
                  value={form.target_id}
                  onChange={(e) => setForm({ ...form, target_id: e.target.value })}
                  className={inputCls(!!errs.target_id)}
                >
                  <option value="">Select…</option>
                  {targetOptions(form.action_kind, instances, gateways, groups).map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                      {o.state && ` — ${o.state}`}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          </Section>

          {/* Live pf preview */}
          <Section title="pf rule preview">
            <pre className="text-xs font-mono text-green-300 bg-black/40 p-3 rounded whitespace-pre-wrap">
              {pfPreview(form, instances, gateways, groups)}
            </pre>
          </Section>

          <div className="flex gap-2 pt-2 border-t border-[var(--border)]">
            <button
              type="submit"
              disabled={submitting}
              className="flex-1 px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
            >
              {submitting ? "Saving…" : editingId ? "Save changes" : "Create policy"}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-2 rounded border border-[var(--border)] text-white text-sm hover:bg-black/30"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
