import React, { Component, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from './Button';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public override state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public override componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('SIEM Copilot Error caught by ErrorBoundary:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public override render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] p-8 text-center bg-bg-app text-text-primary">
          <div className="p-3 bg-critical-bg border border-critical-border rounded-full text-critical-DEFAULT mb-4">
            <AlertTriangle size={32} />
          </div>
          <h2 className="text-lg font-bold text-text-primary mb-2">SOC Interface Encountered an Error</h2>
          <p className="text-sm text-text-secondary max-w-md mb-4">
            An unexpected error interrupted the SIEM dashboard display. You can attempt to reload the component state or refresh the page.
          </p>
          {this.state.error && (
            <pre className="text-2xs font-mono bg-bg-panel border border-border-default rounded p-3 text-critical-text max-w-lg overflow-x-auto text-left mb-6">
              {this.state.error.message}
            </pre>
          )}
          <Button
            variant="primary"
            onClick={this.handleReset}
            leftIcon={<RefreshCw size={14} />}
          >
            Reload Dashboard
          </Button>
        </div>
      );
    }

    return this.props.children;
  }
}
