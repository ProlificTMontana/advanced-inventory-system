import { defineConfig } from "cypress";

export default defineConfig({
  projectId: '8ezpwy',
  allowCypressEnv: false,

  e2e: {
    baseUrl: 'http://localhost:5173',
    setupNodeEvents(on, config) {
      // implement node event listeners here
    },
    specPattern: 'cypress/e2e/**/*.cy.{js,jsx,ts,tsx}',
    supportFile: 'cypress/support/e2e.ts',
  },

  env: {
    apiUrl: 'https://rsatepmxbyoaptrllcpt.supabase.co',
  },
});
