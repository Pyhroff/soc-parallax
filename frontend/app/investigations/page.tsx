"use client";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { MitrePill } from "@/components/ui";

export default function InvestigationsPage() {
  const [entityType, setEntityType] = useState<"user" | "host">("user");
  const [entityId, setEntityId] = useState("ACME\\jdoe");
  const [hours, setHours] = useState(24);

  const m = useMutation({
    mutationFn: () => api.investigate(entityType, entityId, hours),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Autonomous Investigation</h1>
        <p className="text-muted text-sm">
          Deterministic agent: collect → baseline compare → MITRE map → correlate → narrate
        </p>
      </div>

      <form
        onSubmit={(e) => { e.preventDefault(); m.mutate(); }}
        className="flex gap-2 items-center"
      >
        <select
          value={entityType}
          onChange={(e) => setEntityType(e.target.value as "user" | "host")}
          className="bg-panel2 border border-edge rounded px-3 py-1.5 text-sm"
        >
          <option value="user">user</option>
          <option value="host">host</option>
        </select>
        <input
          value={entityId}
          onChange={(e) => setEntityId(e.target.value)}
          className="bg-panel2 border border-edge rounded px-3 py-1.5 text-sm w-64"
        />
        <input
          type="number"
          value={hours}
          onChange={(e) => setHours(+e.target.value)}
          className="bg-panel2 border border-edge rounded px-3 py-1.5 text-sm w-20"
        />
        <span className="text-muted text-xs">hours</span>
        <button className="btn">{m.isPending ? "Running…" : "Investigate"}</button>
      </form>

      {m.error && <div className="text-sev-critical text-sm">Backend unreachable.</div>}

      {m.data && (
        <div className="grid grid-cols-3 gap-6">
          {/* agent reasoning chain — glass box */}
          <div className="card p-5">
            <h2 className="text-xs uppercase text-muted tracking-wide mb-3">Agent reasoning</h2>
            <ol className="space-y-3">
              {m.data.steps.map((s, i) => (
                <li key={i} className="flex gap-3">
                  <span className="text-accent text-xs mt-0.5">{i + 1}</span>
                  <div>
                    <div className="text-xs text-accent">{s.node}</div>
                    <div className="text-sm text-muted">{s.summary}</div>
                  </div>
                </li>
              ))}
            </ol>
          </div>

          <div className="col-span-2 space-y-4">
            <div className="card p-5 border-l-2 border-l-accent">
              <h2 className="text-xs uppercase text-muted tracking-wide mb-2">Narrative</h2>
              <p className="text-sm leading-relaxed whitespace-pre-wrap">{m.data.narrative}</p>
            </div>
            <div className="flex gap-4">
              <div className="card p-4 flex-1">
                <div className="text-xs text-muted uppercase">Detections</div>
                <div className="text-2xl font-semibold">{m.data.detection_count}</div>
              </div>
              <div className="card p-4 flex-[2]">
                <div className="text-xs text-muted uppercase mb-2">Techniques mapped</div>
                <div className="flex gap-1 flex-wrap">
                  {m.data.techniques.map((t) => <MitrePill key={t.technique_id} id={t.technique_id} name={t.name} />)}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
