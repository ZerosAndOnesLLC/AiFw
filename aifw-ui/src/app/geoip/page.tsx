"use client";

import Card from "@/components/Card";
import { useAuth } from "@/context/AuthContext";
import { useGeoip } from "@/hooks/useGeoip";
import { FeedbackBanner } from "@/app/settings/components/FeedbackBanner";
import { AddRuleCard } from "./components/AddRuleCard";
import { DatabaseCard } from "./components/DatabaseCard";
import { LookupCard } from "./components/LookupCard";
import { RulesTable } from "./components/RulesTable";

export default function GeoIpPage() {
  const { permissions } = useAuth();
  const canWrite = permissions.has("geoip:write");
  const g = useGeoip();

  const active = g.rules.filter((r) => r.status === "active");
  const blocked = active.filter((r) => r.action === "block").length;
  const allowed = active.filter((r) => r.action === "allow").length;
  const networks = active.reduce((sum, r) => sum + r.cidr_count, 0);
  const dbLoaded = g.database?.loaded ?? false;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Geo-IP Filtering</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Country-level block and allow rules, backed by MaxMind GeoLite2 data in pf tables.
        </p>
      </div>

      <FeedbackBanner feedback={g.feedback} />

      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <Card title="Countries blocked" value={blocked} color="red" subtitle="active block rules" />
        <Card title="Countries allowed" value={allowed} color="green" subtitle="active allow rules" />
        <Card
          title="Networks in pf"
          value={networks.toLocaleString()}
          color={dbLoaded ? "cyan" : "yellow"}
          subtitle={dbLoaded ? "across active rules" : "no database loaded"}
        />
      </div>

      <DatabaseCard
        db={g.database}
        busy={g.busy}
        canWrite={canWrite}
        onSaveSettings={g.saveDatabaseSettings}
        onRefresh={g.refresh}
        onUpload={g.upload}
      />

      <RulesTable
        rules={g.rules}
        loading={g.loading}
        dbLoaded={dbLoaded}
        busy={g.busy}
        canWrite={canWrite}
        onSave={g.saveRule}
        onDelete={g.removeRule}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <LookupCard dbLoaded={dbLoaded} onLookup={g.lookup} />
        {canWrite && <AddRuleCard busy={g.busy === "add"} onAdd={g.addRule} />}
      </div>
    </div>
  );
}
