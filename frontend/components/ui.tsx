"use client";

export function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    low: "bg-sev-low/20 text-sev-low",
    medium: "bg-sev-medium/20 text-sev-medium",
    high: "bg-sev-high/20 text-sev-high",
    critical: "bg-sev-critical/20 text-sev-critical",
  };
  return <span className={`pill ${map[severity] || "bg-panel2 text-muted"}`}>{severity}</span>;
}

export function StatCard({ label, value, accent }: { label: string; value: React.ReactNode; accent?: boolean }) {
  return (
    <div className="card p-4">
      <div className="text-xs text-muted uppercase tracking-wide">{label}</div>
      <div className={`text-3xl font-semibold mt-1 ${accent ? "text-accent" : ""}`}>{value}</div>
    </div>
  );
}

export function MitrePill({ id, name }: { id: string; name?: string }) {
  return (
    <span className="pill bg-panel2 text-accent border border-edge" title={name}>
      {id}
    </span>
  );
}

export function Loading() {
  return <div className="text-muted text-sm animate-pulse">Loading…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  return (
    <div className="card p-4 border-sev-critical/40 text-sev-critical text-sm">
      Backend unreachable — start the stack (<code>docker compose up</code>) and ingest data.
      <div className="text-muted mt-1">{String(error)}</div>
    </div>
  );
}
