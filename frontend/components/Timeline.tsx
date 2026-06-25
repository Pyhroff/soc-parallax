"use client";
import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { Detection } from "@/lib/api";

const SEV_COLOR: Record<string, string> = {
  low: "#3b82f6", medium: "#eab308", high: "#f97316", critical: "#ef4444",
};

export function Timeline({ detections }: { detections: Detection[] }) {
  const ref = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const pts = detections
      .filter((d) => d.timestamp)
      .map((d) => ({ ...d, t: new Date(d.timestamp as string) }))
      .sort((a, b) => +a.t - +b.t);
    if (pts.length === 0) return;

    const W = ref.current.clientWidth || 800;
    const H = 120;
    const m = { left: 20, right: 20, top: 30, bottom: 30 };
    const svg = d3.select(ref.current);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${W} ${H}`);

    const ext = d3.extent(pts, (d) => d.t) as [Date, Date];
    const pad = Math.max(1000, (+ext[1] - +ext[0]) * 0.05);
    const x = d3.scaleTime()
      .domain([new Date(+ext[0] - pad), new Date(+ext[1] + pad)])
      .range([m.left, W - m.right]);

    // axis line
    svg.append("line")
      .attr("x1", m.left).attr("x2", W - m.right)
      .attr("y1", H / 2).attr("y2", H / 2)
      .attr("stroke", "#222c3c").attr("stroke-width", 2);

    // ticks
    const ax = d3.axisBottom(x).ticks(5).tickFormat(d3.timeFormat("%H:%M:%S") as any);
    svg.append("g")
      .attr("transform", `translate(0,${H - m.bottom})`)
      .call(ax as any)
      .call((g) => g.selectAll("text").attr("fill", "#7a8aa0").attr("font-size", 9))
      .call((g) => g.selectAll("line,path").attr("stroke", "#222c3c"));

    // event dots
    const g = svg.selectAll("g.evt").data(pts).enter().append("g").attr("class", "evt");
    g.append("circle")
      .attr("cx", (d) => x(d.t)).attr("cy", H / 2).attr("r", 7)
      .attr("fill", (d) => SEV_COLOR[d.severity] || "#7a8aa0")
      .attr("stroke", "#0a0e14").attr("stroke-width", 2);
    g.append("title")
      .text((d) => `${d3.timeFormat("%H:%M:%S")(d.t)}  [${d.score}] ${d.entity_id}\n` +
        d.signals.map((s) => "• " + s.evidence).join("\n"));
    g.append("text")
      .attr("x", (d) => x(d.t)).attr("y", H / 2 - 14)
      .attr("text-anchor", "middle").attr("fill", "#7a8aa0").attr("font-size", 8)
      .text((d) => (d.payload?.process?.name) || d.entity_type);
  }, [detections]);

  return <svg ref={ref} className="w-full" style={{ height: 120 }} />;
}
