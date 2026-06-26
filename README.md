# AIMS PWA - Advanced Inventory Management System

A Progressive Web Application for enterprise inventory management, built with Vite, React, TypeScript, and Supabase.

## Tech Stack

- **Frontend**: Vite + React + TypeScript
- **PWA**: Vite PWA (Workbox)
- **State Management**: Zustand (UI state), TanStack Query (server state)
- **Styling**: Tailwind CSS
- **Backend**: Supabase (PostgreSQL, Auth, RLS)
- **Charts**: Recharts
- **Exports**: ExcelJS, PDF-Lib
- **Validation**: Zod
- **Testing**: Cypress (E2E)
- **CI/CD**: GitHub Actions
- **Monitoring**: Sentry

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn
- Supabase account (for backend integration)

### Installation

1. Clone the repository and navigate to the project:
```bash
cd aims-pwa
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env.local
```

Edit `.env.local` and add your Supabase project URL and anon key:
```
VITE_SUPABASE_URL=your-supabase-project-url
VITE_SUPABASE_ANON_KEY=your-supabase-anon-key
VITE_SENTRY_DSN=your-sentry-dsn (optional)
```

**Note:** For Vercel deployment, configure environment variables in the Vercel dashboard instead of committing `.env` files.

### Development

Run the development server:
```bash
npm run dev
```

The application will be available at `http://localhost:5173`

### Build

Build for production:
```bash
npm run build
```

Preview the production build:
```bash
npm run preview
```

### Testing

Run Cypress E2E tests:
```bash
npm run cy:open    # Interactive mode
npm run cy:run     # Headless mode
npm run test:e2e   # Alias for cy:run
```

## CI/CD Pipeline

This project uses GitHub Actions for automated testing and Vercel for deployment.

### Deployment Architecture

**Frontend**: Vercel (automatic deployments)
**CI**: GitHub Actions (testing)
**Error Monitoring**: Sentry
**Backend API**: Supabase
**Database**: Supabase PostgreSQL

### Deployment Flow

```
Feature Branch → Pull Request → GitHub Actions (Tests) → Merge to develop → Vercel Preview
Merge to staging → Vercel Staging
Merge to main → Vercel Production → Sentry Release
```

### GitHub Actions CI

The `.github/workflows/ci.yml` workflow runs on:
- Push to `main`, `develop`, or `staging` branches
- Pull requests to these branches

**CI Steps:**
- Install dependencies
- Run linter
- Run type check
- Build application
- Run Cypress E2E tests

### Vercel Deployment

Vercel automatically deploys the application based on Git branches:

| Git Branch | Vercel Environment |
|------------|-------------------|
| `develop` | Preview Deployment |
| `staging` | Preview Deployment |
| `main` | Production Deployment |
| Pull Requests | Preview Deployment (unique URL) |

### Vercel Setup

1. **Import Repository**
   - Sign up at [vercel.com](https://vercel.com)
   - Import your GitHub repository
   - Vercel will auto-detect the Vite project

2. **Build Settings**
   ```
   Framework Preset: Vite
   Build Command: npm run build
   Output Directory: dist
   Install Command: npm install
   ```

3. **Environment Variables**
   
   Configure in Vercel Project → Settings → Environment Variables:
   
   **Production:**
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
   - `VITE_SENTRY_DSN`
   
   **Preview/Development:**
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
   - `VITE_SENTRY_DSN`

4. **Branch Protection**
   - Enable branch protection rules in GitHub
   - Require CI checks to pass before merging
   - Require pull request reviews

### Required GitHub Secrets

Configure these in GitHub repository settings:

**CI/Testing:**
- `VITE_SUPABASE_URL` - Supabase project URL
- `VITE_SUPABASE_ANON_KEY` - Supabase anon key
- `VITE_SENTRY_DSN` - Sentry DSN (optional for CI)

**Sentry (for release tracking):**
- `SENTRY_AUTH_TOKEN` - Sentry auth token
- `SENTRY_ORG` - Sentry organization slug

## Project Structure

```
aims-pwa/
├── src/
│   ├── components/       # Reusable UI components
│   │   ├── ui/          # Base UI components (Button, Card, Input, etc.)
│   │   ├── layout.tsx   # Main application layout
│   │   ├── offline-banner.tsx
│   │   └── pwa-prompt.tsx
│   ├── context/         # React contexts
│   │   └── theme-context.tsx
│   ├── hooks/           # Custom React hooks
│   ├── lib/             # Utility libraries
│   │   ├── supabase.ts  # Supabase client configuration
│   │   └── sentry.ts    # Sentry error monitoring
│   ├── pages/           # Page components
│   │   ├── login.tsx
│   │   ├── landing.tsx
│   │   ├── dashboard.tsx
│   │   ├── items.tsx
│   │   ├── reports.tsx
│   │   └── settings.tsx
│   ├── store/           # Zustand stores
│   │   └── inventory-store.ts
│   ├── index.css        # Global styles
│   ├── main.tsx         # Application entry point
│   └── vite-env.d.ts    # Vite type declarations
├── cypress/             # E2E tests
│   ├── e2e/            # Test specs
│   │   ├── login.cy.ts
│   │   └── landing.cy.ts
│   └── support/        # Test configuration
├── .github/            # GitHub Actions workflows
│   └── workflows/
│       └── ci.yml
├── public/             # Static assets
├── .env.development    # Development environment variables (local)
├── .env.staging        # Staging environment variables (local)
├── .env.production     # Production environment variables (local)
├── .env.local          # Local environment variables (gitignored)
├── index.html          # HTML template
├── cypress.config.ts   # Cypress configuration
├── vite.config.ts      # Vite configuration
├── tailwind.config.js  # Tailwind CSS configuration
├── tsconfig.json       # TypeScript configuration
└── package.json        # Project dependencies
```

## Features

### Current Implementation

- **Authentication**: Supabase Auth with role-based access control (RBAC)
- **Landing Page**: Professional landing page at root path
- **Dashboard**: Real-time telemetry with charts and KPIs
- **Inventory Management**: Full CRUD operations for items with Supabase
- **Reports**: Report generation with Excel/PDF exports
- **Settings**: Staff management (admin only), theme configuration, user profile
- **PWA**: Service worker, offline banner, install prompt
- **Responsive Design**: Mobile-first, works on all screen sizes
- **E2E Testing**: Cypress test suite for critical user flows
- **CI/CD**: GitHub Actions for automated testing and deployment
- **Error Monitoring**: Sentry integration for production error tracking

### Supabase Integration

The application is fully integrated with Supabase:

1. **Database Schema**: The following tables are in Supabase:
   - `profiles` - User profiles with roles (admin, manager, staff)
   - `categories` - Item categories
   - `suppliers` - Supplier information
   - `items` - Inventory items
   - `inventory_transactions` - Transaction logs

2. **Authentication**: Supabase Auth with email/password
3. **Data Layer**: TanStack Query + Supabase for server state
4. **RLS Policies**: Row-level security for role-based access
5. **Real-time**: Supabase Realtime for live updates

## Database Schema

### Tables

#### profiles
```sql
CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id),
  username TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'manager', 'staff')),
  email TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### categories
```sql
CREATE TABLE categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### suppliers
```sql
CREATE TABLE suppliers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  contact_email TEXT,
  contact_phone TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### items
```sql
CREATE TABLE items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  sku TEXT NOT NULL UNIQUE,
  category_id UUID REFERENCES categories(id),
  supplier_id UUID REFERENCES suppliers(id),
  quantity INTEGER NOT NULL DEFAULT 0,
  min_stock INTEGER NOT NULL DEFAULT 0,
  price NUMERIC NOT NULL DEFAULT 0,
  location TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### inventory_transactions
```sql
CREATE TABLE inventory_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  item_id UUID NOT NULL REFERENCES items(id),
  type TEXT NOT NULL CHECK (type IN ('add', 'remove', 'adjust')),
  quantity_change INTEGER NOT NULL,
  notes TEXT,
  created_by UUID REFERENCES profiles(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Role-Based Access Control

- **Admin**: Full access to all features
- **Manager**: Can manage inventory and view reports
- **Staff**: Read-only access to inventory

## PWA Features

- Installable on desktop and mobile
- Offline support with service worker
- Responsive design
- Push notifications (future)

## License

MIT
