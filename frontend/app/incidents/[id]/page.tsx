"use client";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { SeverityBadge, MitrePill, Loading, ErrorBox } from "@/components/ui";
import { Timeline } from "@/components/Timeline";
import { GraphView } from "@/components/GraphView";

export default function IncidentDetailPage({ params }: { params: { id: string } }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["incident", params.id],
    queryFn: () => api.incident(params.id),
  });
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} />;

  const allSignals = data.detections.flatMap((d) => d.signals);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <SeverityBadge severity={data.severity} />
        <h1 className="text-xl font-semibold">{data.title}</h1>
      </div>

      {/* Narrative — the differentiator */}
      <div className="card p-5 border-l-2 border-l-accent">
        <h2 className="text-xs uppercase text-muted tracking-wide mb-2">Analyst Narrative (grounded)</h2>
        <p className="text-sm leading-relaxed whitespace-pre-wrap">{data.narrative}</p>
      </div>

      <div className="card p-5">
        <h2 className="text-xs uppercase text-muted tracking-wide mb-3">Attack Timeline</h2>
        <Timeline detections={data.detections} />
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Signal breakdown — attributable score */}
        <div className="card p-5">
          <h2 className="text-xs uppercase text-muted tracking-wide mb-3">
            Why this fired — attributable signals
          </h2>
          <div className="space-y-3">
            {allSignals
              .sort((a, b) => b.contribution - a.contribution)
              .map((s, i) => (
                <div key={i} className="border-b border-edge pb-2 last:border-0">
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-accent">{s.name}</span>
                    <span className="text-xs text-muted">+{s.contribution} pts</span>
                  </div>
                  <div className="text-sm mt-0.5">{s.evidence}</div>
                  <div className="flex gap-1 mt-1">
                    {s.mitre.map((m) => <MitrePill key={m.technique_id} id={m.technique_id} name={m.name} />)}
                  </div>
                </div>
              ))}
          </div>
        </div>

        {/* Memory graph subgraph */}
        <div className="space-y-4">
          <div>
            <h2 className="text-xs uppercase text-muted tracking-wide mb-3">Memory Graph</h2>
            <GraphView nodes={data.graph?.nodes || []} height={300} />
          </div>
          {data.similar?.length > 0 && (
            <div className="card p-4">
              <h2 className="text-xs uppercase text-muted tracking-wide mb-2">Similar past incidents</h2>
              {data.similar.map((s) => (
                <div key={s.incident} className="text-xs text-muted">
                  {s.incident.slice(0, 8)} — {s.shared} shared techniques ({s.techniques.join(", ")})
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
