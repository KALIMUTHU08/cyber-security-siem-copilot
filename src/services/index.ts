// ============================================================
// services/index.ts - THE SINGLE SWAP POINT
//
// The API base URL is read from the VITE_API_BASE_URL environment
// variable at build time (set in Vercel dashboard for production).
// Falls back to http://localhost:8000 for local development so no
// .env file is required to run the project locally.
// ============================================================

import type { SiemService } from './SiemService';
import { HttpSiemService } from './api/HttpSiemService';

const _apiBase: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) || 'http://localhost:8000';

export const siemService: SiemService = new HttpSiemService(_apiBase);
