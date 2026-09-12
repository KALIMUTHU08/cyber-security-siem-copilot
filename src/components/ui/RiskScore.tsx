import type { RiskScore } from '../../types';
import { cn, riskLevelColor, ringStrokeDasharrayValues } from '../../lib/utils';

interface RiskScoreBarProps {
  riskScore: RiskScore;
  className?: string;
  showLabel?: boolean;
}

export function RiskScoreBar({ riskScore, className, showLabel = true }: RiskScoreBarProps) {
  const color = riskLevelColor(riskScore.level);
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div className="flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${riskScore.score}%`, backgroundColor: color }}
        />
      </div>
      {showLabel && (
        <span className="text-xs font-mono font-medium tabular-nums" style={{ color }}>
          {riskScore.score}
        </span>
      )}
    </div>
  );
}

interface RiskScoreRingProps {
  riskScore: RiskScore;
  size?: number;
  className?: string;
}

export function RiskScoreRing({ riskScore, size = 80, className }: RiskScoreRingProps) {
  const radius = (size - 12) / 2;
  const { filled, total } = ringStrokeDasharrayValues(riskScore.score, radius);
  const color = riskLevelColor(riskScore.level);
  const cx = size / 2;
  const cy = size / 2;

  return (
    <div className={cn('relative inline-flex items-center justify-center', className)}>
      <svg width={size} height={size} className="-rotate-90">
        {/* Track */}
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke="#21262d"
          strokeWidth="6"
        />
        {/* Fill */}
        <circle
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeDasharray={`${filled} ${total - filled}`}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono font-bold leading-none" style={{ fontSize: size * 0.22, color }}>
          {riskScore.score}
        </span>
        <span className="text-text-muted mt-0.5" style={{ fontSize: size * 0.1 }}>
          / 100
        </span>
      </div>
    </div>
  );
}
