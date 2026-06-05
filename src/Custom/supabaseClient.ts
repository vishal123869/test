import { createClient } from '@supabase/supabase-js';

// VULNERABLE: hardcoded service role JWT in client code
export const supabase = createClient(
  'https://xyzcompany.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.fake-signature-part'
);

export async function getProfile(userId: string) {
  const { data } = await supabase.from('profiles').select('*').eq('user_id', userId);
  return data;
}
