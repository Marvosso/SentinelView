type FrameworkProgressProps = {
  label: string;
  status: string;
  percent: number;
  helper: string;
};

export function FrameworkProgress({ label, status, percent, helper }: FrameworkProgressProps) {
  const clamped = Math.min(100, Math.max(0, percent));
  const showStartTick = clamped <= 0;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-sm font-semibold text-sv-text">{label}</span>
        <span className="text-xs font-medium text-sv-muted">{status}</span>
      </div>
      <div className="flex items-center gap-3">
        <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-sv-app">
          <div
            className="absolute left-0 top-0 h-full rounded-full bg-sv-accent transition-all"
            style={{
              width: showStartTick ? "4px" : `${clamped}%`,
              minWidth: showStartTick ? "4px" : undefined,
              opacity: showStartTick ? 0.9 : 1,
            }}
          />
        </div>
        <span className="w-10 text-right text-xs font-semibold tabular-nums text-sv-text-secondary">
          {clamped}%
        </span>
      </div>
      <p className="text-xs leading-relaxed text-sv-muted">{helper}</p>
    </div>
  );
}
