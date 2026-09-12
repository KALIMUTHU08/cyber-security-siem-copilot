// ============================================================
// services/index.ts — THE SINGLE SWAP POINT
//
// This is the only file that needs to change to switch from
// mock data to a real FastAPI backend.
//
// To integrate a real backend:
// 1. Create src/services/api/HttpSiemService.ts implementing SiemService
// 2. Replace the import below:
//    import { HttpSiemService } from './api/HttpSiemService';
// 3. Replace the instantiation:
//    export const siemService: SiemService = new HttpSiemService('https://your-api.com');
//
// No UI component should change when this swap happens.
// ============================================================

import type { SiemService } from './SiemService';
import { HttpSiemService } from './api/HttpSiemService';

// Real FastAPI backend swap:
export const siemService: SiemService = new HttpSiemService('http://localhost:8000');
