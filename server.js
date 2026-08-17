const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { stringify } = require('csv-stringify/sync');
const { z } = require('zod');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET is required');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000
});

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'rentbook.sid',
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const q = async (text, params = []) => (await pool.query(text, params)).rows;
const one = async (text, params = []) => (await pool.query(text, params)).rows[0] || null;

const clean = v => typeof v === 'string' ? v.trim() : v;
const idSchema = z.coerce.number().int().positive();
const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const moneySchema = z.coerce.number().finite().nonnegative();

function issueCsrf(sessionObj) {
  if (!sessionObj.csrfToken) sessionObj.csrfToken = crypto.randomBytes(24).toString('hex');
  return sessionObj.csrfToken;
}

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function adminOnly(req, res, next) {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Akun viewer hanya dapat melihat data. Hubungi admin untuk melakukan perubahan.' });
  next();
}

function csrf(req, res, next) {
  const token = req.get('x-csrf-token');
  if (!req.session.csrfToken || token !== req.session.csrfToken) return res.status(403).json({ error: 'Invalid CSRF token' });
  next();
}

function validId(value, label) {
  const result = idSchema.safeParse(value);
  if (!result.success) throw new Error(`${label} is invalid`);
  return result.data;
}

async function audit(userId, action, entity, entityId, details = {}) {
  await q(`INSERT INTO audit_logs (user_id, action, entity, entity_id, details) VALUES ($1,$2,$3,$4,$5)`, [userId, action, entity, entityId || null, JSON.stringify(details)]);
}

async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT 'Administrator',
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS apartments (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT,
    city TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS units (
    id BIGSERIAL PRIMARY KEY,
    apartment_id BIGINT NOT NULL REFERENCES apartments(id) ON DELETE CASCADE,
    unit_code TEXT NOT NULL,
    type TEXT,
    status TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available','occupied','maintenance','reserved')),
    monthly_target NUMERIC(14,2) NOT NULL DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(apartment_id, unit_code)
  )`);
  await q(`ALTER TABLE units DROP COLUMN IF EXISTS floor`);
  await q(`ALTER TABLE units DROP COLUMN IF EXISTS tower`);
  await q(`CREATE TABLE IF NOT EXISTS tenants (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    id_number TEXT,
    address TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS leases (
    id BIGSERIAL PRIMARY KEY,
    unit_id BIGINT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    start_date DATE NOT NULL,
    end_date DATE,
    monthly_rent NUMERIC(14,2) NOT NULL DEFAULT 0,
    deposit NUMERIC(14,2) NOT NULL DEFAULT 0,
    billing_day INT NOT NULL DEFAULT 1 CHECK (billing_day BETWEEN 1 AND 28),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','ended','upcoming')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_lease_per_unit ON leases(unit_id) WHERE status='active'`);
  await q(`CREATE TABLE IF NOT EXISTS payments (
    id BIGSERIAL PRIMARY KEY,
    lease_id BIGINT REFERENCES leases(id) ON DELETE SET NULL,
    unit_id BIGINT NOT NULL REFERENCES units(id) ON DELETE RESTRICT,
    tenant_id BIGINT REFERENCES tenants(id) ON DELETE SET NULL,
    payment_date DATE NOT NULL,
    period_month DATE,
    amount NUMERIC(14,2) NOT NULL CHECK(amount >= 0),
    payment_method TEXT NOT NULL DEFAULT 'bank_transfer',
    reference TEXT,
    description TEXT,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS expenses (
    id BIGSERIAL PRIMARY KEY,
    apartment_id BIGINT REFERENCES apartments(id) ON DELETE SET NULL,
    unit_id BIGINT REFERENCES units(id) ON DELETE SET NULL,
    expense_date DATE NOT NULL,
    category TEXT NOT NULL,
    amount NUMERIC(14,2) NOT NULL CHECK(amount >= 0),
    vendor TEXT,
    description TEXT,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_id BIGINT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS guests (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    id_number TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS stays (
    id BIGSERIAL PRIMARY KEY,
    booking_code TEXT UNIQUE NOT NULL,
    unit_id BIGINT NOT NULL REFERENCES units(id) ON DELETE RESTRICT,
    guest_id BIGINT NOT NULL REFERENCES guests(id) ON DELETE RESTRICT,
    check_in DATE NOT NULL,
    check_out DATE NOT NULL,
    nightly_rate NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(nightly_rate >= 0),
    nights INT NOT NULL DEFAULT 1 CHECK(nights >= 1),
    cleaning_fee NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(cleaning_fee >= 0),
    deposit NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(deposit >= 0),
    channel TEXT NOT NULL DEFAULT 'direct',
    payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK(payment_status IN ('unpaid','partial','paid','refunded')),
    status TEXT NOT NULL DEFAULT 'reserved' CHECK(status IN ('reserved','checked_in','checked_out','cancelled')),
    total_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
    notes TEXT,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK(check_out > check_in)
  )`);
  await q(`CREATE INDEX IF NOT EXISTS idx_stays_dates ON stays(check_in, check_out)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_stays_unit_dates ON stays(unit_id, check_in, check_out)`);

  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'viewer'`);
  await q(`CREATE TABLE IF NOT EXISTS apartment_leases (
    id BIGSERIAL PRIMARY KEY,
    apartment_id BIGINT NOT NULL REFERENCES apartments(id) ON DELETE CASCADE,
    landlord_name TEXT,
    start_date DATE NOT NULL,
    end_date DATE,
    monthly_rent NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(monthly_rent >= 0),
    deposit NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK(deposit >= 0),
    payment_day INT NOT NULL DEFAULT 1 CHECK(payment_day BETWEEN 1 AND 28),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','ended','upcoming')),
    notes TEXT,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_apartment_lease ON apartment_leases(apartment_id) WHERE status='active'`);
  await q(`CREATE TABLE IF NOT EXISTS property_partners (
    id BIGSERIAL PRIMARY KEY,
    apartment_id BIGINT NOT NULL REFERENCES apartments(id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    partner_name TEXT NOT NULL,
    share_percent NUMERIC(5,2) NOT NULL CHECK(share_percent > 0 AND share_percent <= 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await q(`CREATE INDEX IF NOT EXISTS idx_property_partners_apartment ON property_partners(apartment_id)`);
  await q(`CREATE TABLE IF NOT EXISTS stay_payments (
    id BIGSERIAL PRIMARY KEY,
    stay_id BIGINT NOT NULL REFERENCES stays(id) ON DELETE CASCADE,
    payment_date DATE NOT NULL,
    amount NUMERIC(14,2) NOT NULL CHECK(amount >= 0),
    payment_method TEXT NOT NULL DEFAULT 'bank_transfer',
    reference TEXT,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  const email = (process.env.ADMIN_EMAIL || 'admin@rentbook.local').toLowerCase().trim();
  const password = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
  const existing = await one(`SELECT id FROM users WHERE email=$1`, [email]);
  if (!existing) {
    const hash = await bcrypt.hash(password, 12);
    await q(`INSERT INTO users(email,password_hash,name,role) VALUES($1,$2,$3,'admin')`, [email, hash, 'Administrator']);
    console.log(`Created initial admin: ${email}`);
  }
}

app.get('/api/health', asyncHandler(async (req,res) => {
  await q('SELECT 1');
  res.json({ ok: true });
}));

app.post('/api/auth/login', loginLimiter, asyncHandler(async (req,res) => {
  const email = clean(req.body.email)?.toLowerCase();
  const password = req.body.password;
  if (!email || !password) return res.status(400).json({ error: 'Email dan password wajib diisi' });
  const user = await one(`SELECT id,email,password_hash,name,role FROM users WHERE email=$1`, [email]);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email atau password salah' });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Login gagal' });
    req.session.user = { id: Number(user.id), email: user.email, name: user.name, role: user.role };
    issueCsrf(req.session);
    res.json({ user: req.session.user, csrfToken: req.session.csrfToken });
  });
}));

app.post('/api/auth/logout', auth, csrf, asyncHandler(async (req,res) => {
  req.session.destroy(() => res.json({ ok: true }));
}));

app.post('/api/auth/change-password', auth, csrf, asyncHandler(async (req,res) => {
  const current = String(req.body.currentPassword || '');
  const nextPassword = String(req.body.newPassword || '');
  if (nextPassword.length < 10) return res.status(400).json({ error: 'Password baru minimal 10 karakter' });
  const user = await one(`SELECT password_hash FROM users WHERE id=$1`, [req.session.user.id]);
  if (!user || !(await bcrypt.compare(current, user.password_hash))) return res.status(400).json({ error: 'Password lama salah' });
  const hash = await bcrypt.hash(nextPassword, 12);
  await q(`UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2`, [hash, req.session.user.id]);
  await audit(req.session.user.id, 'CHANGE_PASSWORD', 'user', req.session.user.id);
  res.json({ ok: true });
}));

app.get('/api/auth/me', asyncHandler(async (req,res) => {
  if (!req.session.user) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: req.session.user, csrfToken: issueCsrf(req.session) });
}));

app.use('/api', auth);
app.use('/api', csrf);

app.get('/api/apartments', asyncHandler(async (req,res) => {
  res.json(await q(`SELECT a.*, COUNT(u.id)::int unit_count, COALESCE(SUM(u.monthly_target),0) target_rent FROM apartments a LEFT JOIN units u ON u.apartment_id=a.id GROUP BY a.id ORDER BY a.id DESC`));
}));
app.post('/api/apartments', asyncHandler(async(req,res)=>{
  const b=req.body; if(!clean(b.name)) return res.status(400).json({error:'Nama apartemen wajib'});
  const r=await one(`INSERT INTO apartments(name,address,city,notes) VALUES($1,$2,$3,$4) RETURNING *`,[clean(b.name),clean(b.address)||null,clean(b.city)||null,clean(b.notes)||null]); await audit(req.session.user.id,'CREATE','apartment',r.id,r); res.status(201).json(r);
}));
app.put('/api/apartments/:id', asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id'), b=req.body; const r=await one(`UPDATE apartments SET name=$1,address=$2,city=$3,notes=$4,updated_at=NOW() WHERE id=$5 RETURNING *`,[clean(b.name),clean(b.address)||null,clean(b.city)||null,clean(b.notes)||null,id]); if(!r)return res.status(404).json({error:'Tidak ditemukan'}); await audit(req.session.user.id,'UPDATE','apartment',id,r); res.json(r);
}));
app.delete('/api/apartments/:id', asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id'); await q(`DELETE FROM apartments WHERE id=$1`,[id]); await audit(req.session.user.id,'DELETE','apartment',id); res.json({ok:true});}));

app.get('/api/units', asyncHandler(async(req,res)=>{
  const apartmentId=req.query.apartment_id?validId(req.query.apartment_id,'apartment_id'):null;
  res.json(await q(`SELECT u.id,u.apartment_id,u.unit_code,u.type,u.status,u.monthly_target,u.notes,u.created_at,u.updated_at,a.name apartment_name,t.name tenant_name,l.monthly_rent active_rent,l.end_date lease_end FROM units u JOIN apartments a ON a.id=u.apartment_id LEFT JOIN leases l ON l.unit_id=u.id AND l.status='active' LEFT JOIN tenants t ON t.id=l.tenant_id ${apartmentId?'WHERE u.apartment_id=$1':''} ORDER BY a.name,u.unit_code`,apartmentId?[apartmentId]:[]));
}));
app.post('/api/units', asyncHandler(async(req,res)=>{
  const b=req.body;
  const apartmentId=validId(b.apartment_id,'apartment_id');
  const unitCode=clean(b.unit_code);
  if(!unitCode)return res.status(400).json({error:'Kode unit wajib diisi'});
  try{
    const r=await one(`INSERT INTO units(apartment_id,unit_code,type,status,monthly_target,notes) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[apartmentId,unitCode,clean(b.type)||'Studio',b.status||'available',moneySchema.parse(b.monthly_target||0),clean(b.notes)||null]);
    await audit(req.session.user.id,'CREATE','unit',r.id,r);
    res.status(201).json(r);
  }catch(e){if(e.code==='23505')return res.status(409).json({error:'Kode unit sudah digunakan pada property tersebut'});throw e;}
}));
app.put('/api/units/:id', asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id');
  const b=req.body;
  const apartmentId=validId(b.apartment_id,'apartment_id');
  const unitCode=clean(b.unit_code);
  if(!unitCode)return res.status(400).json({error:'Kode unit wajib diisi'});
  try{
    const r=await one(`UPDATE units SET apartment_id=$1,unit_code=$2,type=$3,status=$4,monthly_target=$5,notes=$6,updated_at=NOW() WHERE id=$7 RETURNING *`,[apartmentId,unitCode,clean(b.type)||'Studio',b.status||'available',moneySchema.parse(b.monthly_target||0),clean(b.notes)||null,id]);
    if(!r)return res.status(404).json({error:'Unit tidak ditemukan'});
    await audit(req.session.user.id,'UPDATE','unit',id,r);
    res.json(r);
  }catch(e){if(e.code==='23505')return res.status(409).json({error:'Kode unit sudah digunakan pada property tersebut'});throw e;}
}));
app.delete('/api/units/:id', asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id'); await q(`DELETE FROM units WHERE id=$1`,[id]); await audit(req.session.user.id,'DELETE','unit',id); res.json({ok:true});}));

app.get('/api/tenants', asyncHandler(async(req,res)=>{res.json(await q(`SELECT t.*, COUNT(l.id)::int lease_count FROM tenants t LEFT JOIN leases l ON l.tenant_id=t.id GROUP BY t.id ORDER BY t.id DESC`));}));
app.post('/api/tenants', asyncHandler(async(req,res)=>{const b=req.body; if(!clean(b.name))return res.status(400).json({error:'Nama penyewa wajib'}); const r=await one(`INSERT INTO tenants(name,phone,email,id_number,address,notes) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[clean(b.name),clean(b.phone)||null,clean(b.email)||null,clean(b.id_number)||null,clean(b.address)||null,clean(b.notes)||null]); await audit(req.session.user.id,'CREATE','tenant',r.id,r);res.status(201).json(r);}));
app.put('/api/tenants/:id', asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id'),b=req.body; const r=await one(`UPDATE tenants SET name=$1,phone=$2,email=$3,id_number=$4,address=$5,notes=$6,updated_at=NOW() WHERE id=$7 RETURNING *`,[clean(b.name),clean(b.phone)||null,clean(b.email)||null,clean(b.id_number)||null,clean(b.address)||null,clean(b.notes)||null,id]); if(!r)return res.status(404).json({error:'Tidak ditemukan'});await audit(req.session.user.id,'UPDATE','tenant',id,r);res.json(r);}));
app.delete('/api/tenants/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id');await q(`DELETE FROM tenants WHERE id=$1`,[id]);await audit(req.session.user.id,'DELETE','tenant',id);res.json({ok:true});}));

app.get('/api/leases',asyncHandler(async(req,res)=>{res.json(await q(`SELECT l.*,u.unit_code,a.name apartment_name,t.name tenant_name,t.phone tenant_phone FROM leases l JOIN units u ON u.id=l.unit_id JOIN apartments a ON a.id=u.apartment_id JOIN tenants t ON t.id=l.tenant_id ORDER BY l.start_date DESC,l.id DESC`));}));
app.post('/api/leases',asyncHandler(async(req,res)=>{const b=req.body; const unitId=validId(b.unit_id,'unit_id'),tenantId=validId(b.tenant_id,'tenant_id'); const start=dateSchema.parse(b.start_date); const end=b.end_date?dateSchema.parse(b.end_date):null; const rent=moneySchema.parse(b.monthly_rent||0), deposit=moneySchema.parse(b.deposit||0); const client=await pool.connect(); try{await client.query('BEGIN'); if((b.status||'active')==='active'){const conflict=await client.query(`SELECT id FROM leases WHERE unit_id=$1 AND status='active'`,[unitId]);if(conflict.rows.length)throw new Error('Unit sudah memiliki lease aktif');} const r=await client.query(`INSERT INTO leases(unit_id,tenant_id,start_date,end_date,monthly_rent,deposit,billing_day,status,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[unitId,tenantId,start,end,rent,deposit,Number(b.billing_day||1),b.status||'active',clean(b.notes)||null]); if((b.status||'active')==='active') await client.query(`UPDATE units SET status='occupied',updated_at=NOW() WHERE id=$1`,[unitId]); await client.query('COMMIT'); await audit(req.session.user.id,'CREATE','lease',r.rows[0].id,r.rows[0]); res.status(201).json(r.rows[0]);}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}}));
app.put('/api/leases/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id'),b=req.body;const r=await one(`UPDATE leases SET unit_id=$1,tenant_id=$2,start_date=$3,end_date=$4,monthly_rent=$5,deposit=$6,billing_day=$7,status=$8,notes=$9,updated_at=NOW() WHERE id=$10 RETURNING *`,[validId(b.unit_id,'unit_id'),validId(b.tenant_id,'tenant_id'),dateSchema.parse(b.start_date),b.end_date?dateSchema.parse(b.end_date):null,moneySchema.parse(b.monthly_rent||0),moneySchema.parse(b.deposit||0),Number(b.billing_day||1),b.status,clean(b.notes)||null,id]); if(!r)return res.status(404).json({error:'Tidak ditemukan'}); await q(`UPDATE units SET status=CASE WHEN $2='active' THEN 'occupied' ELSE status END WHERE id=$1`,[r.unit_id,r.status]); await audit(req.session.user.id,'UPDATE','lease',id,r);res.json(r);}));
app.delete('/api/leases/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id');const lease=await one(`SELECT unit_id FROM leases WHERE id=$1`,[id]);await q(`DELETE FROM leases WHERE id=$1`,[id]);if(lease)await q(`UPDATE units SET status='available' WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM leases WHERE unit_id=$1 AND status='active')`,[lease.unit_id]);await audit(req.session.user.id,'DELETE','lease',id);res.json({ok:true});}));

app.get('/api/payments',asyncHandler(async(req,res)=>{res.json(await q(`SELECT p.*,u.unit_code,a.name apartment_name,t.name tenant_name FROM payments p JOIN units u ON u.id=p.unit_id JOIN apartments a ON a.id=u.apartment_id LEFT JOIN tenants t ON t.id=p.tenant_id ORDER BY p.payment_date DESC,p.id DESC`));}));
app.post('/api/payments',asyncHandler(async(req,res)=>{const b=req.body;const r=await one(`INSERT INTO payments(lease_id,unit_id,tenant_id,payment_date,period_month,amount,payment_method,reference,description,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[b.lease_id?validId(b.lease_id,'lease_id'):null,validId(b.unit_id,'unit_id'),b.tenant_id?validId(b.tenant_id,'tenant_id'):null,dateSchema.parse(b.payment_date),b.period_month?`${b.period_month}-01`:null,moneySchema.parse(b.amount),clean(b.payment_method)||'bank_transfer',clean(b.reference)||null,clean(b.description)||null,req.session.user.id]);await audit(req.session.user.id,'CREATE','payment',r.id,r);res.status(201).json(r);}));
app.delete('/api/payments/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id');await q(`DELETE FROM payments WHERE id=$1`,[id]);await audit(req.session.user.id,'DELETE','payment',id);res.json({ok:true});}));

app.get('/api/expenses',asyncHandler(async(req,res)=>{res.json(await q(`SELECT e.*,a.name apartment_name,u.unit_code FROM expenses e LEFT JOIN apartments a ON a.id=e.apartment_id LEFT JOIN units u ON u.id=e.unit_id ORDER BY e.expense_date DESC,e.id DESC`));}));
app.post('/api/expenses',asyncHandler(async(req,res)=>{const b=req.body;const r=await one(`INSERT INTO expenses(apartment_id,unit_id,expense_date,category,amount,vendor,description,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[b.apartment_id?validId(b.apartment_id,'apartment_id'):null,b.unit_id?validId(b.unit_id,'unit_id'):null,dateSchema.parse(b.expense_date),clean(b.category),moneySchema.parse(b.amount),clean(b.vendor)||null,clean(b.description)||null,req.session.user.id]);await audit(req.session.user.id,'CREATE','expense',r.id,r);res.status(201).json(r);}));
app.delete('/api/expenses/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id');await q(`DELETE FROM expenses WHERE id=$1`,[id]);await audit(req.session.user.id,'DELETE','expense',id);res.json({ok:true});}));

app.get('/api/guests',asyncHandler(async(req,res)=>{
  res.json(await q(`SELECT g.*,COUNT(s.id)::int stay_count FROM guests g LEFT JOIN stays s ON s.guest_id=g.id GROUP BY g.id ORDER BY g.id DESC`));
}));
app.post('/api/guests',asyncHandler(async(req,res)=>{const b=req.body;if(!clean(b.name))return res.status(400).json({error:'Nama tamu wajib'});const r=await one(`INSERT INTO guests(name,phone,email,id_number,notes) VALUES($1,$2,$3,$4,$5) RETURNING *`,[clean(b.name),clean(b.phone)||null,clean(b.email)||null,clean(b.id_number)||null,clean(b.notes)||null]);await audit(req.session.user.id,'CREATE','guest',r.id,r);res.status(201).json(r);}));
app.put('/api/guests/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id'),b=req.body;const r=await one(`UPDATE guests SET name=$1,phone=$2,email=$3,id_number=$4,notes=$5,updated_at=NOW() WHERE id=$6 RETURNING *`,[clean(b.name),clean(b.phone)||null,clean(b.email)||null,clean(b.id_number)||null,clean(b.notes)||null,id]);if(!r)return res.status(404).json({error:'Tidak ditemukan'});await audit(req.session.user.id,'UPDATE','guest',id,r);res.json(r);}));
app.delete('/api/guests/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id');await q(`DELETE FROM guests WHERE id=$1`,[id]);await audit(req.session.user.id,'DELETE','guest',id);res.json({ok:true});}));

app.get('/api/stays',asyncHandler(async(req,res)=>{
  const month=req.query.month&&/^\d{4}-\d{2}$/.test(req.query.month)?req.query.month:null;
  const where=[];const params=[];
  if(month){params.push(`${month}-01`);where.push(`s.check_in < (date_trunc('month',$1::date) + interval '1 month') AND s.check_out > date_trunc('month',$1::date)`);}
  const cond=where.length?'WHERE '+where.join(' AND '):'';
  res.json(await q(`SELECT s.*,u.unit_code,a.name apartment_name,g.name guest_name,g.phone guest_phone FROM stays s JOIN units u ON u.id=s.unit_id JOIN apartments a ON a.id=u.apartment_id JOIN guests g ON g.id=s.guest_id ${cond} ORDER BY s.check_in,s.unit_id,s.id`,params));
}));
app.post('/api/stays',asyncHandler(async(req,res)=>{
  const b=req.body, unitId=validId(b.unit_id,'unit_id'), guestId=validId(b.guest_id,'guest_id');
  const checkIn=dateSchema.parse(b.check_in), checkOut=dateSchema.parse(b.check_out);
  const nightly=moneySchema.parse(b.nightly_rate||0), cleanFee=moneySchema.parse(b.cleaning_fee||0), dep=moneySchema.parse(b.deposit||0);
  const d1=new Date(`${checkIn}T00:00:00Z`),d2=new Date(`${checkOut}T00:00:00Z`);const nights=Math.max(1,Math.round((d2-d1)/86400000));
  const total=(nightly*nights)+cleanFee; const code=clean(b.booking_code)||`ST-${new Date().toISOString().slice(0,10).replaceAll('-','')}-${Math.random().toString(36).slice(2,7).toUpperCase()}`;
  const overlap=await one(`SELECT id FROM stays WHERE unit_id=$1 AND status<>'cancelled' AND check_in < $3 AND check_out > $2 LIMIT 1`,[unitId,checkOut,checkIn]);
  if(overlap)return res.status(409).json({error:'Unit sudah terbooking pada tanggal tersebut'});
  const r=await one(`INSERT INTO stays(booking_code,unit_id,guest_id,check_in,check_out,nightly_rate,nights,cleaning_fee,deposit,channel,payment_status,status,total_amount,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,[code,unitId,guestId,checkIn,checkOut,nightly,nights,cleanFee,dep,clean(b.channel)||'direct',b.payment_status||'unpaid',b.status||'reserved',total,clean(b.notes)||null,req.session.user.id]);
  await q(`UPDATE units SET status=CASE WHEN $2='checked_in' THEN 'occupied' WHEN $2='reserved' THEN 'reserved' ELSE status END,updated_at=NOW() WHERE id=$1`,[unitId,b.status||'reserved']);
  await audit(req.session.user.id,'CREATE','stay',r.id,r);res.status(201).json(r);
}));
app.put('/api/stays/:id',asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id'),b=req.body,unitId=validId(b.unit_id,'unit_id'),guestId=validId(b.guest_id,'guest_id');
  const checkIn=dateSchema.parse(b.check_in),checkOut=dateSchema.parse(b.check_out);const d1=new Date(`${checkIn}T00:00:00Z`),d2=new Date(`${checkOut}T00:00:00Z`);const nights=Math.max(1,Math.round((d2-d1)/86400000));
  const nightly=moneySchema.parse(b.nightly_rate||0),cleanFee=moneySchema.parse(b.cleaning_fee||0),dep=moneySchema.parse(b.deposit||0),total=(nightly*nights)+cleanFee;
  const overlap=await one(`SELECT id FROM stays WHERE unit_id=$1 AND id<>$2 AND status<>'cancelled' AND check_in < $4 AND check_out > $3 LIMIT 1`,[unitId,id,checkIn,checkOut]);if(overlap)return res.status(409).json({error:'Unit sudah terbooking pada tanggal tersebut'});
  const r=await one(`UPDATE stays SET booking_code=$1,unit_id=$2,guest_id=$3,check_in=$4,check_out=$5,nightly_rate=$6,nights=$7,cleaning_fee=$8,deposit=$9,channel=$10,payment_status=$11,status=$12,total_amount=$13,notes=$14,updated_at=NOW() WHERE id=$15 RETURNING *`,[clean(b.booking_code),unitId,guestId,checkIn,checkOut,nightly,nights,cleanFee,dep,clean(b.channel)||'direct',b.payment_status||'unpaid',b.status||'reserved',total,clean(b.notes)||null,id]);if(!r)return res.status(404).json({error:'Tidak ditemukan'});await audit(req.session.user.id,'UPDATE','stay',id,r);res.json(r);
}));
app.delete('/api/stays/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id');const stay=await one(`SELECT unit_id FROM stays WHERE id=$1`,[id]);await q(`DELETE FROM stays WHERE id=$1`,[id]);if(stay)await q(`UPDATE units SET status='available' WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM stays WHERE unit_id=$1 AND status IN ('reserved','checked_in') AND check_out>CURRENT_DATE) AND NOT EXISTS(SELECT 1 FROM leases WHERE unit_id=$1 AND status='active')`,[stay.unit_id]);await audit(req.session.user.id,'DELETE','stay',id);res.json({ok:true});}));


// --- Property business model: master lease + partner shares ---
app.get('/api/property-financials', asyncHandler(async(req,res)=>{
  const rows=await q(`
    SELECT a.id,a.name,a.city,a.address,
      COALESCE(al.monthly_rent,0) monthly_rent,
      al.start_date master_start,al.end_date master_end,al.status master_status,
      COALESCE((SELECT json_agg(pp ORDER BY pp.id) FROM property_partners pp WHERE pp.apartment_id=a.id),'[]') partners,
      COALESCE((SELECT COUNT(*) FROM units u WHERE u.apartment_id=a.id),0)::int unit_count
    FROM apartments a
    LEFT JOIN apartment_leases al ON al.apartment_id=a.id AND al.status='active'
    ORDER BY a.name`);
  res.json(rows);
}));

app.get('/api/apartment-leases', asyncHandler(async(req,res)=>{
  res.json(await q(`SELECT al.*,a.name apartment_name FROM apartment_leases al JOIN apartments a ON a.id=al.apartment_id ORDER BY al.id DESC`));
}));
app.post('/api/apartment-leases', asyncHandler(async(req,res)=>{
  const b=req.body, apartmentId=validId(b.apartment_id,'apartment_id');
  const start=dateSchema.parse(b.start_date);
  const end=b.end_date?dateSchema.parse(b.end_date):null;
  const rent=moneySchema.parse(b.monthly_rent||0), dep=moneySchema.parse(b.deposit||0);
  const day=Math.min(28,Math.max(1,Number(b.payment_day||1)));
  if(b.status==='active') await q(`UPDATE apartment_leases SET status='ended',updated_at=NOW() WHERE apartment_id=$1 AND status='active'`,[apartmentId]);
  const r=await one(`INSERT INTO apartment_leases(apartment_id,landlord_name,start_date,end_date,monthly_rent,deposit,payment_day,status,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [apartmentId,clean(b.landlord_name)||null,start,end,rent,dep,day,clean(b.status)||'active',clean(b.notes)||null,req.session.user.id]);
  await audit(req.session.user.id,'CREATE','apartment_lease',r.id,r);res.status(201).json(r);
}));
app.put('/api/apartment-leases/:id', asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id'),b=req.body, apartmentId=validId(b.apartment_id,'apartment_id');
  const start=dateSchema.parse(b.start_date),end=b.end_date?dateSchema.parse(b.end_date):null;
  const rent=moneySchema.parse(b.monthly_rent||0),dep=moneySchema.parse(b.deposit||0),day=Math.min(28,Math.max(1,Number(b.payment_day||1)));
  if(b.status==='active') await q(`UPDATE apartment_leases SET status='ended',updated_at=NOW() WHERE apartment_id=$1 AND status='active' AND id<>$2`,[apartmentId,id]);
  const r=await one(`UPDATE apartment_leases SET apartment_id=$1,landlord_name=$2,start_date=$3,end_date=$4,monthly_rent=$5,deposit=$6,payment_day=$7,status=$8,notes=$9,updated_at=NOW() WHERE id=$10 RETURNING *`,
    [apartmentId,clean(b.landlord_name)||null,start,end,rent,dep,day,clean(b.status)||'active',clean(b.notes)||null,id]);
  if(!r)return res.status(404).json({error:'Kontrak tidak ditemukan'});
  await audit(req.session.user.id,'UPDATE','apartment_lease',id,r);res.json(r);
}));
app.delete('/api/apartment-leases/:id',asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id');await q(`DELETE FROM apartment_leases WHERE id=$1`,[id]);await audit(req.session.user.id,'DELETE','apartment_lease',id);res.json({ok:true});
}));

app.get('/api/property-partners',asyncHandler(async(req,res)=>{
  res.json(await q(`SELECT pp.*,a.name apartment_name,u.email user_email FROM property_partners pp JOIN apartments a ON a.id=pp.apartment_id LEFT JOIN users u ON u.id=pp.user_id ORDER BY a.name,pp.id`));
}));
app.post('/api/property-partners',asyncHandler(async(req,res)=>{
  const b=req.body, apartmentId=validId(b.apartment_id,'apartment_id'),share=Number(b.share_percent);
  if(!clean(b.partner_name)||!Number.isFinite(share)||share<=0||share>100)return res.status(400).json({error:'Nama partner dan persentase wajib valid'});
  const total=await one(`SELECT COALESCE(SUM(share_percent),0) value FROM property_partners WHERE apartment_id=$1`,[apartmentId]);
  if(Number(total.value)+share>100.001)return res.status(400).json({error:'Total porsi partner dalam satu property tidak boleh lebih dari 100%'});
  const userId=b.user_id?validId(b.user_id,'user_id'):null;
  const r=await one(`INSERT INTO property_partners(apartment_id,user_id,partner_name,share_percent) VALUES($1,$2,$3,$4) RETURNING *`,[apartmentId,userId,clean(b.partner_name),share]);
  await audit(req.session.user.id,'CREATE','property_partner',r.id,r);res.status(201).json(r);
}));
app.put('/api/property-partners/:id',asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id'),b=req.body,apartmentId=validId(b.apartment_id,'apartment_id'),share=Number(b.share_percent);
  if(!clean(b.partner_name)||!Number.isFinite(share)||share<=0||share>100)return res.status(400).json({error:'Data partner tidak valid'});
  const total=await one(`SELECT COALESCE(SUM(share_percent),0) value FROM property_partners WHERE apartment_id=$1 AND id<>$2`,[apartmentId,id]);
  if(Number(total.value)+share>100.001)return res.status(400).json({error:'Total porsi partner tidak boleh lebih dari 100%'});
  const userId=b.user_id?validId(b.user_id,'user_id'):null;
  const r=await one(`UPDATE property_partners SET apartment_id=$1,user_id=$2,partner_name=$3,share_percent=$4,updated_at=NOW() WHERE id=$5 RETURNING *`,[apartmentId,userId,clean(b.partner_name),share,id]);
  if(!r)return res.status(404).json({error:'Partner tidak ditemukan'});
  await audit(req.session.user.id,'UPDATE','property_partner',id,r);res.json(r);
}));
app.delete('/api/property-partners/:id',asyncHandler(async(req,res)=>{const id=validId(req.params.id,'id');await q(`DELETE FROM property_partners WHERE id=$1`,[id]);await audit(req.session.user.id,'DELETE','property_partner',id);res.json({ok:true});}));

// --- Role / account management ---
app.get('/api/users',asyncHandler(async(req,res)=>{
  if(req.session.user.role!=='admin')return res.status(403).json({error:'Forbidden'});
  res.json(await q(`SELECT id,email,name,role,created_at FROM users ORDER BY name,email`));
}));
app.post('/api/users',asyncHandler(async(req,res)=>{
  const b=req.body,email=clean(b.email)?.toLowerCase(),name=clean(b.name),role=b.role==='admin'?'admin':'viewer';
  if(!email||!name||!b.password||String(b.password).length<8)return res.status(400).json({error:'Nama, email, dan password minimal 8 karakter wajib diisi'});
  const hash=await bcrypt.hash(String(b.password),12);
  try{
    const r=await one(`INSERT INTO users(email,password_hash,name,role) VALUES($1,$2,$3,$4) RETURNING id,email,name,role`,[email,hash,name,role]);
    await audit(req.session.user.id,'CREATE','user',r.id,r);res.status(201).json(r);
  }catch(e){if(e.code==='23505')return res.status(409).json({error:'Email akun sudah digunakan'});throw e;}
}));
app.put('/api/users/:id',asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id'),b=req.body,role=b.role==='admin'?'admin':'viewer';
  if(id===Number(req.session.user.id) && role!=='admin')return res.status(400).json({error:'Akun admin yang sedang digunakan tidak boleh diubah menjadi viewer'});
  const fields=[],vals=[];
  fields.push('name=$1');vals.push(clean(b.name)||'User');
  fields.push('role=$2');vals.push(role);
  if(b.password){if(String(b.password).length<8)return res.status(400).json({error:'Password minimal 8 karakter'});fields.push('password_hash=$3');vals.push(await bcrypt.hash(String(b.password),12));}
  vals.push(id);
  const r=await one(`UPDATE users SET ${fields.join(',')},updated_at=NOW() WHERE id=$${vals.length} RETURNING id,email,name,role`,vals);
  if(!r)return res.status(404).json({error:'User tidak ditemukan'});
  await audit(req.session.user.id,'UPDATE','user',id,r);res.json(r);
}));
app.delete('/api/users/:id',asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id');if(id===Number(req.session.user.id))return res.status(400).json({error:'Akun yang sedang login tidak dapat dihapus'});
  await q(`DELETE FROM users WHERE id=$1`,[id]);await audit(req.session.user.id,'DELETE','user',id);res.json({ok:true});
}));

app.get('/api/stay-payments',asyncHandler(async(req,res)=>{
  res.json(await q(`SELECT sp.*,s.booking_code,g.name guest_name,u.unit_code,a.name apartment_name FROM stay_payments sp JOIN stays s ON s.id=sp.stay_id JOIN guests g ON g.id=s.guest_id JOIN units u ON u.id=s.unit_id JOIN apartments a ON a.id=u.apartment_id ORDER BY sp.payment_date DESC,sp.id DESC`));
}));
app.post('/api/stay-payments',asyncHandler(async(req,res)=>{
  const b=req.body,stayId=validId(b.stay_id,'stay_id'),amount=moneySchema.parse(b.amount||0);
  const r=await one(`INSERT INTO stay_payments(stay_id,payment_date,amount,payment_method,reference,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[stayId,dateSchema.parse(b.payment_date||new Date().toISOString().slice(0,10)),amount,clean(b.payment_method)||'bank_transfer',clean(b.reference)||null,req.session.user.id]);
  const total=await one(`SELECT total_amount FROM stays WHERE id=$1`,[stayId]),paid=await one(`SELECT COALESCE(SUM(amount),0) value FROM stay_payments WHERE stay_id=$1`,[stayId]);
  const status=Number(paid.value)>=Number(total.total_amount)?'paid':Number(paid.value)>0?'partial':'unpaid';
  await q(`UPDATE stays SET payment_status=$2,updated_at=NOW() WHERE id=$1`,[stayId,status]);
  await audit(req.session.user.id,'CREATE','stay_payment',r.id,r);res.status(201).json(r);
}));
app.delete('/api/stay-payments/:id',asyncHandler(async(req,res)=>{
  const id=validId(req.params.id,'id'),p=await one(`SELECT stay_id FROM stay_payments WHERE id=$1`,[id]);await q(`DELETE FROM stay_payments WHERE id=$1`,[id]);
  if(p){const paid=await one(`SELECT COALESCE(SUM(amount),0) value FROM stay_payments WHERE stay_id=$1`,[p.stay_id]),t=await one(`SELECT total_amount FROM stays WHERE id=$1`,[p.stay_id]);const status=Number(paid.value)>=Number(t.total_amount)?'paid':Number(paid.value)>0?'partial':'unpaid';await q(`UPDATE stays SET payment_status=$2 WHERE id=$1`,[p.stay_id,status]);}
  await audit(req.session.user.id,'DELETE','stay_payment',id);res.json({ok:true});
}));

app.get('/api/dashboard',asyncHandler(async(req,res)=>{
  const from=req.query.from&&/^\d{4}-\d{2}-\d{2}$/.test(req.query.from)?req.query.from:null;
  const to=req.query.to&&/^\d{4}-\d{2}-\d{2}$/.test(req.query.to)?req.query.to:null;
  const payParams=[]; const expParams=[]; const payWhere=[]; const expWhere=[];
  if(from){payWhere.push(`payment_date >= $${payParams.length+1}`);payParams.push(from);expWhere.push(`expense_date >= $${expParams.length+1}`);expParams.push(from);}
  if(to){payWhere.push(`payment_date <= $${payParams.length+1}`);payParams.push(to);expWhere.push(`expense_date <= $${expParams.length+1}`);expParams.push(to);}
  const payCondition=payWhere.length?'WHERE '+payWhere.join(' AND '):''; const expCondition=expWhere.length?'WHERE '+expWhere.join(' AND '):'';
  const [income,expense,masterRent,units,active,arrears,monthly,byApartment] = await Promise.all([
    one(`SELECT COALESCE(SUM(s.total_amount),0) value FROM stays s WHERE s.status <> 'cancelled' ${from?`AND s.check_out >= $1`:''} ${to?`AND s.check_in <= $${from?2:1}`:''}`, from&&to?[from,to]:from?[from]:to?[to]:[]),
    one(`SELECT COALESCE(SUM(amount),0) value FROM expenses ${expCondition}`,expParams),
    one(`SELECT COALESCE(SUM(monthly_rent),0) value FROM apartment_leases WHERE status='active'`),
    one(`SELECT COUNT(*) value FROM units`),
    one(`SELECT COUNT(*) value FROM units WHERE status='occupied'`),
    one(`SELECT COALESCE(SUM(GREATEST(l.monthly_rent - COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.lease_id=l.id AND p.period_month=DATE_TRUNC('month', CURRENT_DATE)),0),0)),0) value FROM leases l WHERE l.status='active'`),
    q(`SELECT TO_CHAR(DATE_TRUNC('month',payment_date),'YYYY-MM') AS "month",COALESCE(SUM(amount),0) value FROM payments GROUP BY 1 ORDER BY 1 DESC LIMIT 12`),
    q(`SELECT a.name,SUM(u.monthly_target) target,COUNT(*) units,COUNT(*) FILTER(WHERE u.status='occupied') occupied FROM apartments a LEFT JOIN units u ON u.apartment_id=a.id GROUP BY a.id ORDER BY a.name`)
  ]);
  const gross=Number(income.value), operating=Number(expense.value), rentCost=Number(masterRent.value);
  res.json({income:gross,expense:operating,masterRent:rentCost,profit:gross-operating-rentCost,units:Number(units.value),occupied:Number(active.value),occupancy:Number(units.value)?Number(active.value)/Number(units.value)*100:0,arrears:Number(arrears.value),monthly,byApartment});
}));

app.get('/api/reports/monthly',asyncHandler(async(req,res)=>{
  res.json(await q(`WITH months AS (SELECT DATE_TRUNC('month',CURRENT_DATE) - (n||' month')::interval m FROM generate_series(0,11) n)
  SELECT TO_CHAR(months.m,'YYYY-MM') AS "month",
  COALESCE((SELECT SUM(p.amount) FROM payments p WHERE DATE_TRUNC('month',p.payment_date)=months.m),0) income,
  COALESCE((SELECT SUM(e.amount) FROM expenses e WHERE DATE_TRUNC('month',e.expense_date)=months.m),0) expense
  FROM months ORDER BY months.m DESC`));
}));

app.get('/api/audit',asyncHandler(async(req,res)=>{res.json(await q(`SELECT l.*,u.email FROM audit_logs l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 100`));}));

const exportQueries={
  payments:`SELECT p.payment_date,p.period_month,a.name apartment,u.unit_code,t.name tenant,p.amount,p.payment_method,p.reference,p.description FROM payments p JOIN units u ON u.id=p.unit_id JOIN apartments a ON a.id=u.apartment_id LEFT JOIN tenants t ON t.id=p.tenant_id ORDER BY p.payment_date DESC`,
  expenses:`SELECT e.expense_date,a.name apartment,u.unit_code,e.category,e.amount,e.vendor,e.description FROM expenses e LEFT JOIN apartments a ON a.id=e.apartment_id LEFT JOIN units u ON u.id=e.unit_id ORDER BY e.expense_date DESC`,
  leases:`SELECT a.name apartment,u.unit_code,t.name tenant,l.start_date,l.end_date,l.monthly_rent,l.deposit,l.billing_day,l.status FROM leases l JOIN units u ON u.id=l.unit_id JOIN apartments a ON a.id=u.apartment_id JOIN tenants t ON t.id=l.tenant_id ORDER BY l.start_date DESC`
};
app.get('/api/export/:type',asyncHandler(async(req,res)=>{const sql=exportQueries[req.params.type];if(!sql)return res.status(404).json({error:'Export tidak tersedia'});const rows=await q(sql);const csv=stringify(rows,{header:true});res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename=rentbook-${req.params.type}-${new Date().toISOString().slice(0,10)}.csv`);res.send(csv);}));

app.use(express.static(path.join(__dirname,'public')));
app.get(/.*/,(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.use((err,req,res,next)=>{console.error(err);const msg=err?.code==='23505'?'Data duplikat / konflik':err?.message||'Server error';res.status(400).json({error:msg});});

initDb().then(()=>app.listen(PORT,()=>console.log(`RentBook running on port ${PORT}`))).catch(err=>{console.error('DB init failed',err);process.exit(1);});
