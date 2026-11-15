"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { Shell } from "@/components/shell";
import { DetailHost } from "@/components/sheets";
import { Skeleton } from "@/components/ui/misc";
import { useAuth } from "@/lib/auth";
import { DetailProvider } from "@/lib/detail";
import { LiveProvider } from "@/lib/live";
import { OriginProvider } from "@/lib/origin";

export default function AppLayout({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  if (loading || !user) {
    return (
      <div className="mx-auto max-w-5xl space-y-4 px-6 py-10" aria-busy="true">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  return (
    <OriginProvider>
      <LiveProvider>
        <DetailProvider>
          <Shell>{children}</Shell>
          <DetailHost />
        </DetailProvider>
      </LiveProvider>
    </OriginProvider>
  );
}
