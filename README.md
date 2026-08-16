# RentBook Apartemen — Full Stack

A production-oriented apartment rental bookkeeping application built with Node.js, Express, PostgreSQL, server-side sessions, and a responsive vanilla JS frontend.

## Features

- Secure login/logout with hashed passwords and PostgreSQL-backed sessions
- Apartment/property and unit management
- Tenant management
- Lease management with monthly rent, deposit, start/end dates and status
- Payment tracking with payment method and reference
- Expense tracking by unit/property
- Dashboard KPIs: revenue, expenses, profit, occupancy, overdue/outstanding rent
- Monthly financial report and CSV exports
- Audit log for important write operations
- Responsive dark SaaS UI
- Railway-ready via GitHub or CLI
- Automatic schema bootstrap on startup

## Local setup

1. Create a PostgreSQL database.
2. Copy `.env.example` to `.env` and update values.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

The app creates its tables automatically. An initial admin account is created from `ADMIN_EMAIL` and `ADMIN_PASSWORD` on first startup if it does not exist.

## Railway deployment

1. Push this repository to GitHub.
2. In Railway, create a new project and deploy the GitHub repo.
3. Add a PostgreSQL service.
4. Add these variables to the app service:
   - `DATABASE_URL=${{Postgres.DATABASE_URL}}`
   - `SESSION_SECRET=<long random secret>`
   - `ADMIN_EMAIL=<your admin email>`
   - `ADMIN_PASSWORD=<strong first-login password>`
   - `NODE_ENV=production`
5. Deploy. Railway detects the Node app automatically and the app listens on Railway's `PORT`.
6. Generate a public domain under Networking.

## Security notes

- Never commit `.env`.
- Change the initial admin password after first login.
- Use HTTPS in production (Railway public domains use HTTPS).
- Rotate `SESSION_SECRET` deliberately; rotating it invalidates active sessions.
