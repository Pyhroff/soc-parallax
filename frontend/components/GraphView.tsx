"use client";
import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

export interface GNode { id: string; label: string }
export interface GEdge { source: string; target: string; label?: string }

const LABEL_COLOR: Record<string, string> = {
  User: "#38bdf8", Host: "#a78bfa", Process: "#34d399",
  IP: "#f97316", Domain: "#eab308", FileHash: "#94a3b8",
  Incident: "#ef4444", Technique: "#f472b6",
};

export function GraphView({ nodes, edges, height = 460 }: { nodes: GNode[]; edges?: GEdge[]; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const els: cytoscape.ElementDefinition[] = [
      ...nodes.map((n) => ({ data: { id: n.id, label: `${n.id}`, type: n.label } })),
      ...(edges || [])
        .filter((e) => nodes.find((n) => n.id === e.source) && nodes.find((n) => n.id === e.target))
        .map((e) => ({ data: { id: `${e.source}->${e.target}`, source: e.source, target: e.target, label: e.label || "" } })),
    ];

    const cy = cytoscape({
      container: ref.current,
      elements: els,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: "#e6edf3",
            "font-size": 9,
            "background-color": (n: any) => LABEL_COLOR[n.data("type")] || "#7a8aa0",
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 26, height: 26,
          },
        },
        {
          selector: "edge",
          style: {
            label: "data(label)",
            "font-size": 7,
            color: "#7a8aa0",
            width: 1.5,
            "line-color": "#222c3c",
            "target-arrow-color": "#222c3c",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
          },
        },
      ],
      layout: { name: "cose", animate: false, padding: 30 },
    });
    return () => cy.destroy();
  }, [nodes, edges]);

  return <div ref={ref} className="card" style={{ height }} />;
}
