# Study Planner (student + faculty) - Vercel ready

```
api/index.py     serverless Python API (PostgreSQL on Vercel, SQLite locally)
db/schema.sql    all SQL tables, keys, indexes
public/          frontend (served by Vercel CDN)
vercel.json  requirements.txt  package.json
```

Tables: accounts, tasks, assignments, attendance, goals, notes, courses, posted, posted_targets, progress.

Local: `npm run dev` (or `python api/index.py`) -> http://localhost:5050
Update after changes: `npm run push`   Redeploy: `npm run deploy`
Env vars: DATABASE_URL (set by Vercel Postgres), FACULTY_CODE (faculty sign-up code), SECRET_KEY (optional).
