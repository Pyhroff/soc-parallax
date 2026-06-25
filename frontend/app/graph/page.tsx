"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { GraphView, GNode, GEdge } from "@/components/GraphView";

export default function GraphPage() {
  const [entity, setEntity] = useState("ACME\\jdoe");
  const [submitted, setSubmitted] = useState(entity);

  const { data, error, isFetching } = useQuery({
    queryKey: ["blast", submitted],
    queryFn: () => api_blast(submitted),
    enabled: !!submitted,
  });

  // build graph elements from blast-radius rows
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  if (data) {
    nodes.push({ id: submitted, label: "User" });
    for (const row of data) {
      nodes.push({ id: row.host, label: "Host" });
      edges.push({ source: submitted, target: row.host, label: "logged into" });
      for (const ip of row.external_ips || []) {
        if (!ip) continue;
        nodes.push({ id: ip, label: "IP" });
        edges.push({ source: row.host, target: ip, label: "connected" });
      }
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Organizational Memory Graph</h1>
      <form
        onSubmit={(e) => { e.preventDefault(); setSubmitted(entity); }}
        className="flex gap-2"
      >
        <input
          value={entity}
          onChange={(e) => setEntity(e.target.value)}
          placeholder="user e.g. ACME\jdoe"
          className="bg-panel2 border border-edge rounded px-3 py-1.5 text-sm w-72"
        />
        <button className="btn">Explore blast radius</button>
        {isFetching && <span className="text-muted text-sm self-center">querying…</span>}
      </form>
      {error && <div className="text-sev-critical text-sm">Graph empty or backend down.</div>}
      <GraphView nodes={dedupe(nodes)} edges={edges} />
      <p className="text-xs text-muted">
        Hosts this user touched and the external IPs those hosts contacted — lateral-movement view.
      </p>
    </div>
  );
}

function dedupe(nodes: GNode[]): GNode[] {
  const seen = new Set<string>();
  return nodes.filter((n) => (seen.has(n.id) ? false : (seen.add(n.id), true)));
}

async function api_blast(entity: string) {
  const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  const res = await fetch(`${base}/graph/blast-radius?entity=${encodeURIComponent(entity)}`, { cache: "no-store" });
  if (!res.ok) throw new Error("blast radius failed");
  return res.json() as Promise<{ host: string; external_ips: string[] }[]>;
}
