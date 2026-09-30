// Lazily exposed dependency bridge to keep flowLog free of circular imports at runtime.
import { createClient } from '@supabase/supabase-js';
const required = (key: string) => {
  const v = process.env[key];
  if (!v) throw new Error(`Missing environment variable: ${key}`);
  return v;
};
export const supabase = createClient(required('SUPABASE_URL'), required('SUPABASE_SERVICE_ROLE_KEY'));
