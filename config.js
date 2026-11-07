/* Portal settings. Leave the Supabase values empty to run the browser-only demo.
   Fill both to switch the page to a real backend (accounts, Google sign-in, database).
   These two values are public by design: access is enforced by the row-level security
   policies in supabase/schema.sql. Never put a service_role key here. */
window.PORTAL_CONFIG = {
  supabaseUrl: '',      // e.g. https://abcdxyz.supabase.co
  supabaseAnonKey: '',  // the "anon public" key from Project Settings > API
  showDemoLogin: true,  // false hides the quick-login buttons for the demo accounts
  googleClientId: ''    // only used by the browser-only demo; real Google sign-in is set up inside Supabase
};
