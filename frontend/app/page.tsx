"use client";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { StatCard, MitrePill, Loading, ErrorBox } from "@/components/ui";

export default function OverviewPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["overview"], queryFn: api.overview });

  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} />;

  const sev = data.detections_by_severity || {};
  const maxTech = Math.max(1, ...data.top_techniques.map((t) => t.n));

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Command Center</h1>
        <p className="text-muted text-sm">Live behavioral risk across the environment</p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Events ingested" value={data.events.toLocaleString()} />
        <StatCard label="Detections" value={data.detections.toLocaleString()} />
        <StatCard label="Incidents" value={data.incidents.toLocaleString()} />
        <StatCard label="Open incidents" value={data.open_incidents} accent />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="card p-5">
          <h2 className="text-sm uppercase text-muted tracking-wide mb-4">Detections by severity</h2>
          <div className="space-y-3">
            {["critical", "high", "medium", "low"].map((s) => {
              const n = sev[s] || 0;
              const total = Object.values(sev).reduce((a, b) => a + b, 0) || 1;
              return (
                <div key={s}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="capitalize">{s}</span>
                    <span className="text-muted">{n}</span>
                  </div>
                  <div className="h-2 bg-panel2 rounded overflow-hidden">
                    <div
                      className={`h-full bg-sev-${s}`}
                      style={{ width: `${(n / total) * 100}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card p-5">
          <h2 className="text-sm uppercase text-muted tracking-wide mb-4">Top MITRE techniques</h2>
          <div className="space-y-2">
            {data.top_techniques.length === 0 && (
              <div className="text-muted text-sm">No detections yet — ingest data.</div>
            )}
            {data.top_techniques.map((t) => (
              <div key={t.technique_id} className="flex items-center gap-3">
                <div className="w-44 truncate">
                  <MitrePill id={t.technique_id} /> <span className="text-xs text-muted">{t.name}</span>
                </div>
                <div className="flex-1 h-2 bg-panel2 rounded overflow-hidden">
                  <div className="h-full bg-accent" style={{ width: `${(t.n / maxTech) * 100}%` }} />
                </div>
                <span className="text-xs text-muted w-6 text-right">{t.n}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
