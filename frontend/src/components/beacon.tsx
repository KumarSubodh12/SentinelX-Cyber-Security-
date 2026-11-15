import { cn } from "@/lib/utils";

export type Posture = "critical" | "high" | "attention" | "calm";

const DOT: Record<Posture, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  attention: "bg-sev-medium",
  calm: "bg-good",
};

export const POSTURE_TEXT: Record<Posture, string> = {
  critical: "Critical alerts need attention",
  high: "High-severity alerts are open",
  attention: "Some alerts are waiting for review",
  calm: "No active alerts",
};

/**
 * SentinelX's mark: a ring with a dot. The dot shows the current posture (highest active severity) and
 * a single ripple plays when `pulseKey` changes, i.e. when a new alert arrives.
 */
export function Beacon({ posture, pulseKey = 0, size = 28 }: { posture: Posture; pulseKey?: number; size?: number }) {
  return (
    <span className="relative inline-flex shrink-0 items-center justify-center" style={{ width: size, height: size }} role="img" aria-label={POSTURE_TEXT[posture]}>
      <span className="absolute inset-0 rounded-full border border-ink-3/70" />
      <span className="absolute inset-[22%] rounded-full border border-line" />
      {pulseKey > 0 ? (
        <span key={pulseKey} className={cn("absolute h-1/4 w-1/4 animate-beacon rounded-full", DOT[posture])} />
      ) : null}
      <span className={cn("relative h-[26%] w-[26%] rounded-full", DOT[posture])} />
    </span>
  );
}
