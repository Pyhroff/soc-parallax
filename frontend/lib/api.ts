const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts?.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} on ${path}`);
  return res.json() as Promise<T>;
}

export const api = {
  overview: () => req<Overview>("/overview"),
  incidents: () => req<Incident[]>("/incidents"),
  incident: (id: string) => req<IncidentDetail>(`/incidents/${id}`),
  detections: (sev?: string) =>
    req<Detection[]>(`/detections${sev ? `?severity=${sev}` : ""}`),
  investigate: (entity_type: string, entity_id: string, window_hours = 24) =>
    req<Investigation>("/investigate", {
      method: "POST",
      body: JSON.stringify({ entity_type, entity_id, window_hours }),
    }),
  predictNext: (technique_id: string) =>
    req<NextTechnique[]>(`/predict/next?technique_id=${technique_id}`),
  health: () => req<Record<string, string>>("/health"),
};

// ---- types ----
export interface Overview {
  events: number; detections: number; incidents: number; open_incidents: number;
  detections_by_severity: Record<string, number>;
  top_techniques: { technique_id: string; name: string; n: number }[];
}
export interface MitreRef { technique_id: string; tactic: string; name: string; }
export interface Signal {
  name: string; weight: number; sub_score: number; contribution: number;
  evidence: string; mitre: MitreRef[];
}
export interface Detection {
  detection_id: string; event_id: string; entity_type: string; entity_id: string;
  score: number; severity: string; signals: Signal[]; mitre: MitreRef[]; created_at?: string;
  timestamp?: string; payload?: any;
}
export interface Incident {
  incident_id: string; title: string; status: string; severity: string;
  entity_type: string; entity_id: string; detection_ids: string[];
  mitre_chain: MitreRef[]; created_at: string;
}
export interface IncidentDetail extends Incident {
  narrative: string;
  detections: Detection[];
  graph: { nodes: { id: string; label: string }[] };
  similar: { incident: string; shared: number; techniques: string[] }[];
}
export interface Investigation {
  entity_type: string; entity_id: string; window_hours: number;
  steps: { node: string; summary: string }[];
  detection_count: number; techniques: MitreRef[];
  related: any; narrative: string; detections: Detection[];
}
export interface NextTechnique { technique_id: string; name: string; observed: number; }
