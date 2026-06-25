"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { MitrePill } from "@/components/ui";

export default function PredictionsPage() {
  const [tech, setTech] = useState("T1059.001");
  const [submitted, setSubmitted] = useState(tech);

  const { data, isFetching } = useQuery({
    queryKey: ["predict", submitted],
    queryFn: () => api.predictNext(submitted),
    enabled: !!submitted,
  });

  const max = Math.max(1, ...(data || []).map((d) => d.observed));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Threat Evolution Predictor</h1>
        <p className="text-muted text-sm">
          Given an observed technique, what historically came next (from the memory graph PRECEDES chain).
        </p>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); setSubmitted(tech); }} className="flex gap-2">
        <input
          value={tech}
          onChange={(e) => setTech(e.target.value)}
          placeholder="T1059.001"
          className="bg-panel2 border border-edge rounded px-3 py-1.5 text-sm w-48"
        />
        <button className="btn">Predict next</button>
        {isFetching && <span className="text-muted text-sm self-center">…</span>}
      </form>

      <div className="card p-5">
        <div className="flex items-center gap-2 mb-4 text-sm">
          <MitrePill id={submitted} /> <span className="text-muted">likely leads to →</span>
        </div>
        {(!data || data.length === 0) && (
          <div className="text-muted text-sm">
            No successor data yet. Predictions populate as incidents are correlated
            (the PRECEDES edges are built from real attack sequences).
          </div>
        )}
        <div className="space-y-2">
          {data?.map((d) => (
            <div key={d.technique_id} className="flex items-center gap-3">
              <div className="w-44"><MitrePill id={d.technique_id} /> <span className="text-xs text-muted">{d.name}</span></div>
              <div className="flex-1 h-2 bg-panel2 rounded overflow-hidden">
                <div className="h-full bg-accent" style={{ width: `${(d.observed / max) * 100}%` }} />
              </div>
              <span className="text-xs text-muted w-10 text-right">{d.observed}×</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
