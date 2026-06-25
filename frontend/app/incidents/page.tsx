"use client";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { SeverityBadge, MitrePill, Loading, ErrorBox } from "@/components/ui";

export default function IncidentsPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["incidents"], queryFn: api.incidents });
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} />;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Incidents</h1>
      {data.length === 0 && <div className="text-muted text-sm">No incidents yet.</div>}
      <div className="space-y-3">
        {data.map((inc) => (
          <Link
            key={inc.incident_id}
            href={`/incidents/${inc.incident_id}`}
            className="card p-4 block hover:border-accent transition"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <SeverityBadge severity={inc.severity} />
                <span className="font-medium">{inc.title}</span>
              </div>
              <span className="text-xs text-muted">
                {new Date(inc.created_at).toLocaleString()}
              </span>
            </div>
            <div className="flex gap-2 mt-3 flex-wrap">
              {inc.mitre_chain?.map((m) => <MitrePill key={m.technique_id} id={m.technique_id} name={m.name} />)}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
