import { Shield, Brain, ListChecks } from 'lucide-react';
import { cn } from '../../lib/utils';

// ---- Observed Evidence Block ----
interface ObservedEvidenceBlockProps {
  items: string[];
  className?: string;
}

export function ObservedEvidenceBlock({ items, className }: ObservedEvidenceBlockProps) {
  return (
    <div className={cn('border-l-2 border-accent rounded-r-md bg-accent-subtle p-4', className)}>
      <div className="flex items-center gap-2 mb-3">
        <Shield size={14} className="text-accent flex-shrink-0" />
        <span className="text-xs font-semibold text-accent uppercase tracking-wider">Observed Evidence</span>
      </div>
      <ul className="space-y-1.5">
        {items.map((item, i) => (
          <li key={i} className="flex gap-2 text-sm text-text-secondary">
            <span className="text-accent font-mono mt-0.5 flex-shrink-0">›</span>
            <span className="leading-relaxed">{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---- AI Assessment Block ----
interface AiAssessmentBlockProps {
  content: string;
  className?: string;
}

export function AiAssessmentBlock({ content, className }: AiAssessmentBlockProps) {
  return (
    <div className={cn('border-l-2 border-ai rounded-r-md bg-ai-subtle p-4', className)}>
      <div className="flex items-center gap-2 mb-3">
        <Brain size={14} className="text-ai flex-shrink-0" />
        <span className="text-xs font-semibold text-ai uppercase tracking-wider">AI Assessment</span>
        <span className="ml-auto inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-ai-muted text-ai text-2xs font-medium">
          <span className="w-1 h-1 rounded-full bg-ai animate-pulse-slow" />
          Copilot
        </span>
      </div>
      <p className="text-sm text-text-secondary leading-relaxed italic">{content}</p>
    </div>
  );
}

// ---- Recommendations Block ----
interface RecommendationsBlockProps {
  items: string[];
  className?: string;
}

export function RecommendationsBlock({ items, className }: RecommendationsBlockProps) {
  return (
    <div className={cn('border-l-2 border-low rounded-r-md bg-low-bg p-4', className)}>
      <div className="flex items-center gap-2 mb-3">
        <ListChecks size={14} className="text-low-DEFAULT flex-shrink-0" />
        <span className="text-xs font-semibold text-low-text uppercase tracking-wider">Recommended Next Steps</span>
      </div>
      <ol className="space-y-1.5 list-none">
        {items.map((item, i) => (
          <li key={i} className="flex gap-2.5 text-sm text-text-secondary">
            <span className="text-low-DEFAULT font-mono font-bold flex-shrink-0 mt-0.5 tabular-nums min-w-[1.2rem]">
              {i + 1}.
            </span>
            <span className="leading-relaxed">{item}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
