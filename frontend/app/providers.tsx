"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { refetchInterval: 5000, staleTime: 2000 } } }),
  );
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
