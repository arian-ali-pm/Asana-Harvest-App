# Asana / Harvest Dashboard

Per-user dashboard that puts Asana estimates, Asana logged time, and Harvest actual time side by side. Built for Prosperity Media to track project burn against estimate.

## What it does

- Search your Asana tasks and Harvest projects.
- Track items in a unified dashboard with estimated vs actual vs Harvest hours.
- Auto-refreshes Harvest hours on a configurable interval.
- Optionally pushes Harvest hours back into Asana's "Actual time" field.
- Multi-user: each colleague signs in with their Google account and keeps their own dashboard.

## Deployment

This app runs on Render (free) backed by Supabase (free Postgres). Total cost: $0/month for small teams.

### One-time setup

#### 1. Supabase database

1. Sign up at [supabase.com](https://supabase.com).
2. New project. Region: pick the one closest to Sydney (`ap-southeast-2`).
3. Set a strong database password. Save it.
4. Wait ~2 minutes for the project to provision.
5. Project Settings > Database > Connection string > URI. Pick the "Transaction" pooler URL. It looks like:
   ```
   postgresql://postgres.xxxxx:[YOUR-PASSWORD]@aws-0-ap-southeast-2.pooler.supabase.com:6543/postgres
   ```
6. Replace `postgresql://` with `postgresql+psycopg://` at the start. Save this whole URL.

#### 2. Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com).
2. Create or select a project.
3. APIs & Services > OAuth consent screen.
   - User Type: **External** (yes, even though only Prosperity emails will use it).
   - App name: `Asana Harvest Dashboard`.
   - User support email: yours.
   - Developer contact: yours.
   - Save and continue through the next screens. No scopes to add beyond default.
   - Test users: add yourself for now.
4. APIs & Services > Credentials > Create Credentials > OAuth client ID.
   - Application type: **Web application**.
   - Authorised redirect URIs:
     - `http://localhost:8765/auth/google/callback` (for local dev)
     - `https://YOUR-APP.onrender.com/auth/google/callback` (you'll fill this in after step 3 below)
5. Save the Client ID and Client Secret.

#### 3. Render deploy

1. Sign up at [render.com](https://render.com). No credit card required.
2. New > Blueprint.
3. Connect this GitHub repo.
4. Render reads `render.yaml` and prompts for the missing env vars:
   - `APP_BASE_URL`: leave blank for now, you'll set it after deploy.
   - `ALLOWED_EMAIL_DOMAINS`: `prosperitymedia.com.au`
   - `DATABASE_URL`: the Supabase URL from step 1.
   - `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`: from step 2.
5. Apply and wait for the first deploy (~3 min).
6. Once deployed, copy the URL (e.g. `https://asana-harvest-dashboard.onrender.com`).
7. Go back to Render > your service > Environment, set `APP_BASE_URL` to that URL. Save.
8. Go back to Google Cloud > Credentials > your OAuth client, add `https://your-url.onrender.com/auth/google/callback` to Authorised redirect URIs. Save.
9. Visit the URL. Sign in with Google. Enter your Asana and Harvest tokens. Done.

#### 4. Onboarding colleagues

Share the Render URL. They click "Sign in with Google", pick their @prosperitymedia.com.au account, and follow the setup screen to enter their own Asana and Harvest tokens.

You may need to add their email as a "Test user" in Google Cloud Console > OAuth consent screen for the first ~100 users, until you publish the app (Production mode). For an internal tool with under 100 users, Test mode is fine.

## Local development

```bash
# Clone, install, copy env file
git clone https://github.com/arian-ali-pm/Asana-Harvest-App
cd Asana-Harvest-App
pip install -r requirements.txt
cp .env.example .env
# Edit .env: paste your Google OAuth credentials, set DATABASE_URL=sqlite:///./local.db
# Generate FERNET_KEY with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

python asanaharvestdashboard.py
# Open http://localhost:8765
```

## Security notes

- Asana and Harvest tokens are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256) before being written to the database. The key lives in the `FERNET_KEY` env var and is never committed.
- Session cookies are signed with `SESSION_SECRET`. HTTPS is enforced by Render.
- Each colleague should create their own dedicated Asana and Harvest tokens (Asana allows naming PATs so they can be revoked individually). When someone leaves Prosperity, their Google account stops working and their stored tokens become inert; we recommend they revoke their tokens in Asana/Harvest as well.

## Tokens to create

Each user needs to create their own:

- **Asana Personal Access Token**: [app.asana.com/0/my-apps](https://app.asana.com/0/my-apps)
- **Harvest Account ID + Personal Access Token**: [id.getharvest.com/developers](https://id.getharvest.com/developers)
