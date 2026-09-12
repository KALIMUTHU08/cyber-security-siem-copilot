import { useState, useEffect, useCallback, useRef } from 'react';

type AsyncState<T> =
  | { status: 'idle'; data: null; error: null }
  | { status: 'loading'; data: null; error: null }
  | { status: 'success'; data: T; error: null }
  | { status: 'error'; data: null; error: Error };

export function useAsync<T>(
  asyncFn: () => Promise<T>,
  deps: React.DependencyList = [],
): AsyncState<T> & { refetch: () => void } {
  const [state, setState] = useState<AsyncState<T>>({
    status: 'loading',
    data: null,
    error: null,
  });

  const mountedRef = useRef(true);

  const execute = useCallback(() => {
    setState({ status: 'loading', data: null, error: null });
    try {
      asyncFn()
        .then((data) => {
          if (mountedRef.current) {
            setState({ status: 'success', data, error: null });
          }
        })
        .catch((err: unknown) => {
          if (mountedRef.current) {
            setState({
              status: 'error',
              data: null,
              error: err instanceof Error ? err : new Error(String(err)),
            });
          }
        });
    } catch (err: unknown) {
      if (mountedRef.current) {
        setState({
          status: 'error',
          data: null,
          error: err instanceof Error ? err : new Error(String(err)),
        });
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    mountedRef.current = true;
    execute();
    return () => {
      mountedRef.current = false;
    };
  }, [execute]);

  return { ...state, refetch: execute };
}
