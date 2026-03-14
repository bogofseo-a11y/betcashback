require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const multer = require('multer');
const sharp = require('sharp');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const TelegramBot = require('node-telegram-bot-api');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// DB
// ============================================================
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ============================================================
// TELEGRAM BOT
// ============================================================
const bot = new TelegramBot(process.env.BOT_TOKEN, { polling: false });

// ============================================================
// MIDDLEWARE
// ============================================================
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use('/uploads', express.static('uploads'));
app.use('/admin-panel', express.static(path.join(__dirname, 'admin')));
app.use('/', express.static(path.join(__dirname, '../frontend')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests' } });
app.use('/api/', limiter);

// Stricter limiter for claim submission
const claimLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: 'Too many claims' } });

// ============================================================
// FILE UPLOAD (secure)
// ============================================================
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024, files: 5 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Invalid file type'));
  }
});

const partnerImportUpload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowedMimes = [
      'text/csv',
      'application/csv',
      'application/vnd.ms-excel',
      'text/plain',
      'application/octet-stream',
    ];
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (allowedMimes.includes(file.mimetype) || ext === '.csv') cb(null, true);
    else cb(new Error('Only CSV files are supported in MVP'));
  }
});

// Ensure uploads dir
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads', { recursive: true });

async function processAndSaveImage(buffer, originalname) {
  const filename = crypto.randomBytes(16).toString('hex') + '.jpg';
  const filepath = path.join('uploads', filename);
  // Re-encode (strip EXIF, sanitize)
  await sharp(buffer)
    .jpeg({ quality: 85 })
    .toFile(filepath);
  return { filename, filepath };
}

// ============================================================
// TELEGRAM initData VERIFICATION
// ============================================================
function verifyTelegramInitData(initData) {
  if (!initData) return null;
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    params.delete('hash');
    const dataCheckString = [...params.entries()]
      .sort(([a],[b]) => a.localeCompare(b))
      .map(([k,v]) => `${k}=${v}`)
      .join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData')
      .update(process.env.BOT_TOKEN)
      .digest();
    const expectedHash = crypto.createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');
    if (expectedHash !== hash) return null;
    // Check auth_date not older than 24h
    const authDate = parseInt(params.get('auth_date'));
    if (Date.now() / 1000 - authDate > 86400) return null;
    const userStr = params.get('user');
    return userStr ? JSON.parse(userStr) : null;
  } catch { return null; }
}

// Auth middleware
function authMiddleware(req, res, next) {
  // In development mode, allow bypass
  if (process.env.NODE_ENV === 'development') {
    req.tgUser = { id: 12345, first_name: 'Dev', username: 'dev_user' };
    return next();
  }
  const initData = req.headers['x-telegram-init-data'];
  const user = verifyTelegramInitData(initData);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.tgUser = user;
  next();
}

// ============================================================
// TIER SYSTEM (по кол-ву подтверждённых заявок — лояльность, не сумма проигрышей)
// Tier 1: 0-4 заявок  → 5%
// Tier 2: 5-14 заявок → 7%
// Tier 3: 15+ заявок  → 10%
// ============================================================
const TIERS = [
  { tier: 1, pct: 5,  minClaims: 0 },
  { tier: 2, pct: 7,  minClaims: 5 },
  { tier: 3, pct: 10, minClaims: 15 },
];

async function getUserTier(userId) {
  const result = await pool.query(`
    SELECT COUNT(*) as total
    FROM claims
    WHERE user_id = $1 AND status IN ('approved', 'paid')
  `, [userId]);
  const total = parseInt(result.rows[0].total);
  const tier = [...TIERS].reverse().find(t => total >= t.minClaims) || TIERS[0];
  const nextTier = TIERS.find(t => t.tier === tier.tier + 1);
  return {
    tier: tier.tier, pct: tier.pct, progress: total,
    nextTierAt: nextTier ? nextTier.minClaims : tier.minClaims,
  };
}

// ============================================================
// RISK SCORING
// ============================================================
async function calculateRiskScore(userId, betId, lossAmount) {
  let score = 0;
  
  // Check duplicate bet ID
  const dupBet = await pool.query('SELECT id FROM claims WHERE bet_id = $1 LIMIT 1', [betId]);
  if (dupBet.rows.length) score += 80;
  
  // New account (< 7 days)
  const user = await pool.query('SELECT created_at FROM users WHERE id = $1', [userId]);
  if (user.rows.length) {
    const age = (Date.now() - new Date(user.rows[0].created_at)) / 86400000;
    if (age < 7) score += 20;
  }
  
  // High first claim
  const claimCount = await pool.query('SELECT COUNT(*) as cnt FROM claims WHERE user_id = $1', [userId]);
  if (parseInt(claimCount.rows[0].cnt) === 0 && lossAmount > 10000) score += 15;
  
  // Too many claims today
  const todayClaims = await pool.query(`
    SELECT COUNT(*) as cnt FROM claims 
    WHERE user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
  `, [userId]);
  if (parseInt(todayClaims.rows[0].cnt) >= 3) score += 25;
  
  // Round number (possible fraud signal)
  if (lossAmount % 1000 === 0 && lossAmount > 5000) score += 10;
  
  return Math.min(score, 100);
}

// ============================================================
// ENSURE/GET USER
// ============================================================
async function ensureUser(tgUser, referrerId = null) {
  const { id, first_name, last_name, username } = tgUser;
  const result = await pool.query(`
    INSERT INTO users (id, first_name, last_name, username, referrer_id)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (id) DO UPDATE SET
      first_name = EXCLUDED.first_name,
      last_name = EXCLUDED.last_name,
      username = EXCLUDED.username,
      updated_at = NOW()
    RETURNING *
  `, [id, first_name, last_name || null, username || null, referrerId]);
  return result.rows[0];
}

async function getSettingNumber(key, fallback = 0) {
  try {
    const res = await pool.query('SELECT value FROM app_settings WHERE key = $1 LIMIT 1', [key]);
    if (!res.rows.length) return fallback;
    const n = parseFloat(res.rows[0].value);
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

async function getUserWithdrawableSummary(userId, client = pool) {
  // MVP invariants (freeze checklist):
  // 1) bookmaker_accounts.status = verification status (manual admin decision)
  // 2) claims can be submitted only with verified bookmaker account
  // 3) partner suggestions are advisory only (no auto-verification)
  // 4) payout availability = approved claims - reserved payout requests
  // MVP accounting rule (conservative): withdrawable pool is only claims in `approved` status.
  // Then we reserve/subtract all payout requests that are already created and not safely reversible.
  // available = approved_claims - reserved_payout_requests
  const claimRes = await client.query(`
    SELECT COALESCE(SUM(cashback_amount_rub), 0) as approved_total
    FROM claims
    WHERE user_id = $1 AND status = 'approved'
  `, [userId]);

  const reservedRes = await client.query(`
    SELECT COALESCE(SUM(amount_rub), 0) as reserved_total
    FROM payout_requests
    WHERE user_id = $1
      AND status IN ('pending', 'approved', 'processing', 'paid')
  `, [userId]);

  const approvedTotal = parseFloat(claimRes.rows[0]?.approved_total || 0);
  const reservedTotal = parseFloat(reservedRes.rows[0]?.reserved_total || 0);
  const available = Math.max(0, approvedTotal - reservedTotal);

  return {
    approvedTotal,
    reservedTotal,
    available,
  };
}

// ============================================================
// ROUTES
// ============================================================

// Health check
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date() }));

// ---- USER ----
app.post('/api/auth/start', authMiddleware, async (req, res) => {
  try {
    const { ref } = req.body || {};
    const referrerId = ref ? parseInt(ref.replace('ref_','')) : null;
    const user = await ensureUser(req.tgUser, referrerId);
    const tierInfo = await getUserTier(user.id);
    
    // Balance
    const balRes = await pool.query(`
      SELECT 
        COALESCE(SUM(CASE WHEN status='paid' THEN cashback_amount_rub ELSE 0 END),0) as earned,
        COALESCE(SUM(CASE WHEN status='approved' THEN cashback_amount_rub ELSE 0 END),0) as pending
      FROM claims WHERE user_id = $1
    `, [user.id]);
    
    // Ref stats
    const refRes = await pool.query(`
      SELECT COUNT(DISTINCT referred_user_id) as count,
             COALESCE(SUM(amount_rub),0) as income
      FROM referral_ledger WHERE referrer_user_id = $1
    `, [user.id]);
    
    res.json({
      user,
      tierInfo,
      balance: parseFloat(balRes.rows[0].pending),
      totalEarned: parseFloat(balRes.rows[0].earned),
      refStats: {
        count: parseInt(refRes.rows[0].count),
        income: parseFloat(refRes.rows[0].income),
      }
    });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---- CLAIMS ----
app.get('/api/claims', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, b.name as bookmaker_name
      FROM claims c
      JOIN bookmakers b ON b.id = c.bookmaker_id
      WHERE c.user_id = $1
      ORDER BY c.created_at DESC
      LIMIT 50
    `, [req.tgUser.id]);
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/claims', authMiddleware, claimLimiter, upload.array('files', 5), async (req, res) => {
  try {
    const { bookmaker_id, affiliate_player_id, loss_amount, bet_id, bet_date, comment } = req.body;
    const bookmakerId = parseInt(bookmaker_id);

    if (!Number.isInteger(bookmakerId) || !loss_amount || !bet_id || !bet_date) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (parseFloat(loss_amount) <= 0) return res.status(400).json({ error: 'Invalid amount' });
    if (!req.files?.length) return res.status(400).json({ error: 'At least 1 screenshot required' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Ensure user
      await ensureUser(req.tgUser);

      // Claims are allowed only for verified bookmaker account
      const accountRes = await client.query(`
        SELECT * FROM bookmaker_accounts
        WHERE user_id = $1 AND bookmaker_id = $2
        LIMIT 1
      `, [req.tgUser.id, bookmakerId]);

      if (!accountRes.rows.length) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: 'Сначала зарегистрируйтесь у букмекера и отправьте player ID на проверку.'
        });
      }

      const account = accountRes.rows[0];
      if (account.status !== 'verified') {
        await client.query('ROLLBACK');
        const msg = account.status === 'pending'
          ? 'Ваш player ID ещё на проверке. Дождитесь подтверждения букмекера.'
          : 'Player ID отклонён. Отправьте корректный ID в разделе «Букмекеры».';
        return res.status(403).json({ error: msg });
      }

      if (affiliate_player_id && String(affiliate_player_id).trim() && String(affiliate_player_id).trim() !== String(account.affiliate_player_id || '')) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Player ID не совпадает с подтверждённым аккаунтом букмекера.' });
      }

      // Get tier
      const tier = await getUserTier(req.tgUser.id);
      const cashback = parseFloat(loss_amount) * (tier.pct / 100);

      // Risk score
      const riskScore = await calculateRiskScore(req.tgUser.id, bet_id, parseFloat(loss_amount));

      // Create claim
      const claimRes = await client.query(`
        INSERT INTO claims (user_id, bookmaker_id, bookmaker_account_id, affiliate_player_id, loss_amount_rub, bet_id, bet_date, comment, status, cashback_percent, cashback_amount_rub, risk_score)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'submitted',$9,$10,$11)
        RETURNING *
      `, [req.tgUser.id, bookmakerId, account.id, account.affiliate_player_id || null, loss_amount, bet_id, bet_date, comment || null, tier.pct, cashback, riskScore]);
      
      const claim = claimRes.rows[0];
      
      // Process and save files
      for (const file of req.files) {
        const { filename } = await processAndSaveImage(file.buffer, file.originalname);
        const fileHash = crypto.createHash('md5').update(file.buffer).digest('hex');
        
        // Check for duplicate file hash
        const dupFile = await client.query('SELECT id FROM claim_attachments WHERE file_hash = $1', [fileHash]);
        
        await client.query(`
          INSERT INTO claim_attachments (claim_id, file_url, file_hash, is_duplicate)
          VALUES ($1,$2,$3,$4)
        `, [claim.id, `/uploads/${filename}`, fileHash, dupFile.rows.length > 0]);
      }
      
      // Audit log
      await client.query(`
        INSERT INTO audit_log (actor_type, actor_id, action, entity, entity_id, payload_json)
        VALUES ('user', $1, 'claim_submitted', 'claim', $2, $3)
      `, [req.tgUser.id, claim.id, JSON.stringify({ risk_score: riskScore })]);
      
      await client.query('COMMIT');
      
      // Notify admin
      if (process.env.ADMIN_CHAT_ID) {
        const riskEmoji = riskScore > 60 ? '🔴' : riskScore > 30 ? '🟡' : '🟢';
        bot.sendMessage(process.env.ADMIN_CHAT_ID, 
          `${riskEmoji} Новая заявка #${claim.id}\n` +
          `👤 @${req.tgUser.username || req.tgUser.id}\n` +
          `🏦 BK ID: ${bookmakerId}\n` +
          `💸 Проигрыш: ${parseFloat(loss_amount).toLocaleString('ru-RU')}₽\n` +
          `💰 Кэшбэк: ${cashback.toLocaleString('ru-RU')}₽ (${tier.pct}%)\n` +
          `⚠️ Риск: ${riskScore}/100`
        ).catch(() => {});
      }
      
      // Notify user with exact SLA deadline
      const deadline = new Date(Date.now() + 24 * 60 * 60 * 1000);
      const deadlineStr = deadline.toLocaleString('ru-RU', {
        day: '2-digit', month: '2-digit',
        hour: '2-digit', minute: '2-digit',
        timeZone: 'Europe/Moscow'
      });
      bot.sendMessage(req.tgUser.id,
        `✅ Заявка #${claim.id} принята!\n\n` +
        `💰 Ожидаемый кэшбэк: ${cashback.toLocaleString('ru-RU')}₽\n` +
        `⏱ Проверим до ${deadlineStr} МСК\n\n` +
        `Если появятся вопросы — пишите в поддержку.`
      ).catch(() => {});
      
      res.json({ success: true, claim_id: claim.id, cashback });
    } catch(e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch(e) {
    console.error('Claim error:', e);
    res.status(500).json({ error: e.message || 'Server error' });
  }
});

function isValidTrackingMode(mode) {
  return ['none', 'subid', 'clickid', 'subid_clickid'].includes(mode);
}

function sanitizeParamName(name, fallback) {
  const value = (name || fallback || '').trim();
  return /^[a-zA-Z_][a-zA-Z0-9_]{0,49}$/.test(value) ? value : null;
}

function validateBookmakerPayload(payload = {}) {
  const errors = [];
  const trackingMode = payload.tracking_mode || 'none';
  const affiliateTemplate = (payload.affiliate_url_template || '').trim();

  if (!payload.name || !String(payload.name).trim()) errors.push('name is required');
  if (!isValidTrackingMode(trackingMode)) errors.push('Invalid tracking_mode');

  const isActive = payload.is_active !== false;
  if ((isActive || trackingMode !== 'none') && !affiliateTemplate) {
    errors.push('affiliate_url_template is required for active bookmakers');
  }

  if (trackingMode === 'subid' || trackingMode === 'subid_clickid') {
    if (!sanitizeParamName(payload.tracking_subid_param, 'subid')) errors.push('Invalid tracking_subid_param');
  }
  if (trackingMode === 'clickid' || trackingMode === 'subid_clickid') {
    if (!sanitizeParamName(payload.tracking_clickid_param, 'clickid')) errors.push('Invalid tracking_clickid_param');
  }

  if (affiliateTemplate) {
    try {
      const u = new URL(affiliateTemplate);
      if (!['http:', 'https:'].includes(u.protocol)) errors.push('affiliate_url_template must be http/https');
    } catch {
      errors.push('affiliate_url_template must be a valid URL');
    }
  }

  return errors;
}

async function sendUserNotificationSafe(userId, message) {
  try {
    if (!userId || !message) return;
    await bot.sendMessage(userId, message);
  } catch (e) {
    console.error('User notification send failed:', { userId, error: e?.message || e });
  }
}

function generateTrackingToken(type) {
  const rand = crypto.randomBytes(10).toString('hex');
  const prefix = type === 'subid' ? 's' : 'c';
  return `${prefix}_${Date.now().toString(36)}_${rand}`;
}

function buildTrackedUrl(bookmaker, userId) {
  const mode = bookmaker.tracking_mode || 'none';
  const template = (bookmaker.affiliate_url_template || '').trim();

  if (!template) throw new Error('Affiliate URL template is not configured');

  const subidParam = sanitizeParamName(bookmaker.tracking_subid_param, 'subid');
  const clickidParam = sanitizeParamName(bookmaker.tracking_clickid_param, 'clickid');

  if ((mode === 'subid' || mode === 'subid_clickid') && !subidParam) {
    throw new Error('Invalid subid parameter config');
  }
  if ((mode === 'clickid' || mode === 'subid_clickid') && !clickidParam) {
    throw new Error('Invalid clickid parameter config');
  }

  const generatedSubid = (mode === 'subid' || mode === 'subid_clickid')
    ? generateTrackingToken('subid')
    : null;
  const generatedClickid = (mode === 'clickid' || mode === 'subid_clickid')
    ? generateTrackingToken('clickid')
    : null;

  const finalUrl = new URL(template);

  if (generatedSubid) {
    finalUrl.searchParams.set(subidParam, generatedSubid);
  }
  if (generatedClickid) {
    finalUrl.searchParams.set(clickidParam, generatedClickid);
  }

  return {
    generatedSubid,
    generatedClickid,
    finalUrl: finalUrl.toString(),
    trackingMode: mode,
  };
}


function parseCsvLine(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      out.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  out.push(cur.trim());
  return out;
}

function parseDateSafe(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function parseNumberSafe(value) {
  if (value === null || value === undefined || value === '') return null;
  const cleaned = String(value).replace(/\s/g, '').replace(',', '.');
  const n = parseFloat(cleaned);
  return Number.isFinite(n) ? n : null;
}

function normalizeCsvRow(raw = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(raw)) lower[String(k).toLowerCase()] = v;

  const importedPlayerId = lower.player_id || lower.playerid || lower.affiliate_player_id || lower.userid || lower.user_id || null;
  const importedSubid = lower.subid || lower.sub_id || lower.s1 || null;
  const importedClickid = lower.clickid || lower.click_id || lower.c1 || null;
  const registrationDate = lower.registration_date || lower.registered_at || lower.reg_date || null;
  const lastActivityAt = lower.last_activity_at || lower.activity_at || lower.last_activity || null;
  const totalDepositRub = lower.total_deposit_rub || lower.deposit_rub || lower.deposits || null;
  const totalGgrRub = lower.total_ggr_rub || lower.ggr_rub || lower.ggr || null;
  const externalRowId = lower.external_row_id || lower.row_id || null;

  return {
    external_row_id: externalRowId ? String(externalRowId) : null,
    imported_player_id: importedPlayerId ? String(importedPlayerId) : null,
    imported_subid: importedSubid ? String(importedSubid) : null,
    imported_clickid: importedClickid ? String(importedClickid) : null,
    registration_date: parseDateSafe(registrationDate),
    last_activity_at: parseDateSafe(lastActivityAt),
    total_deposit_rub: parseNumberSafe(totalDepositRub),
    total_ggr_rub: parseNumberSafe(totalGgrRub),
    raw_payload_json: raw,
  };
}

function parsePartnerCsv(buffer) {
  const text = buffer.toString('utf8').replace(/^﻿/, '');
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (!lines.length) return [];
  const headers = parseCsvLine(lines[0]).map(h => h.trim());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const values = parseCsvLine(lines[i]);
    if (!values.some(v => String(v || '').trim())) continue;
    const raw = {};
    headers.forEach((h, idx) => { raw[h || `col_${idx + 1}`] = values[idx] ?? ''; });
    rows.push(normalizeCsvRow(raw));
  }
  return rows;
}

function getBookmakerParser(bookmaker) {
  const key = String(bookmaker.short_name || bookmaker.name || 'default').toLowerCase();
  const parsers = {
    '1x': parsePartnerCsv,
    'fb': parsePartnerCsv,
    'bc': parsePartnerCsv,
    'mb': parsePartnerCsv,
    'bb': parsePartnerCsv,
    default: parsePartnerCsv,
  };
  return parsers[key] || parsers.default;
}

function buildDiffKey(row) {
  return row.imported_player_id || row.imported_subid || row.imported_clickid || row.external_row_id || crypto.createHash('md5').update(JSON.stringify(row.raw_payload_json || {})).digest('hex');
}

function isRowChanged(prev, next) {
  const fields = ['imported_player_id','imported_subid','imported_clickid','registration_date','last_activity_at','total_deposit_rub','total_ggr_rub'];
  return fields.some(f => String(prev?.[f] ?? '') !== String(next?.[f] ?? ''));
}

function calcDateDiffDays(a, b) {
  if (!a || !b) return null;
  const d1 = new Date(a);
  const d2 = new Date(b);
  if (Number.isNaN(d1.getTime()) || Number.isNaN(d2.getTime())) return null;
  return Math.floor(Math.abs(d1.getTime() - d2.getTime()) / (24 * 60 * 60 * 1000));
}

function buildSuggestionScore({ playerIdMatch, subidMatch, clickidMatch, registrationDateDiffDays }) {
  let score = 0;
  const reasons = [];

  if (playerIdMatch) {
    score += 70;
    reasons.push('player_id_exact_match');
  }
  if (subidMatch) {
    score += 45;
    reasons.push('subid_exact_match_via_generated_link');
  }
  if (clickidMatch) {
    score += 45;
    reasons.push('clickid_exact_match_via_generated_link');
  }
  if (subidMatch && clickidMatch) {
    score += 10;
    reasons.push('subid_and_clickid_both_match');
  }
  if (registrationDateDiffDays !== null) {
    if (registrationDateDiffDays <= 3) {
      score += 10;
      reasons.push('registration_date_near_account_created_at_<=3d');
    } else if (registrationDateDiffDays <= 7) {
      score += 5;
      reasons.push('registration_date_near_account_created_at_<=7d');
    }
  }

  score = Math.max(0, Math.min(100, score));
  const confidenceLevel = score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
  return { score, confidenceLevel, reasons };
}

async function upsertPartnerMatchSuggestion(client, {
  bookmakerAccountId,
  partnerPlayerRowId,
  score,
  confidenceLevel,
  reasons,
  payload,
}) {
  await client.query(`
    INSERT INTO partner_match_suggestions
      (bookmaker_account_id, partner_player_row_id, confidence_score, confidence_level, reasons, suggestion_payload_json, created_at)
    VALUES ($1,$2,$3,$4,$5,$6,NOW())
    ON CONFLICT (bookmaker_account_id, partner_player_row_id)
    DO UPDATE SET
      confidence_score = EXCLUDED.confidence_score,
      confidence_level = EXCLUDED.confidence_level,
      reasons = EXCLUDED.reasons,
      suggestion_payload_json = EXCLUDED.suggestion_payload_json,
      created_at = NOW()
  `, [
    bookmakerAccountId,
    partnerPlayerRowId,
    score,
    confidenceLevel,
    reasons,
    JSON.stringify(payload || {}),
  ]);
}

async function generateSuggestionsForImportedRow(client, row) {
  const candidateMap = new Map();

  if (row.imported_player_id) {
    const playerIdMatches = await client.query(`
      SELECT ba.id, ba.user_id, ba.bookmaker_id, ba.affiliate_player_id, ba.created_at
      FROM bookmaker_accounts ba
      WHERE ba.bookmaker_id = $1 AND ba.affiliate_player_id = $2
    `, [row.bookmaker_id, row.imported_player_id]);

    for (const account of playerIdMatches.rows) {
      candidateMap.set(account.id, {
        account,
        playerIdMatch: true,
        subidMatch: false,
        clickidMatch: false,
      });
    }
  }

  if (row.imported_subid || row.imported_clickid) {
    const tokenMatches = await client.query(`
      SELECT DISTINCT ba.id, ba.user_id, ba.bookmaker_id, ba.affiliate_player_id, ba.created_at,
             blg.generated_subid, blg.generated_clickid
      FROM bookmaker_link_generations blg
      JOIN bookmaker_accounts ba
        ON ba.user_id = blg.user_id
       AND ba.bookmaker_id = blg.bookmaker_id
      WHERE blg.bookmaker_id = $1
        AND (
          ($2::text IS NOT NULL AND blg.generated_subid = $2)
          OR
          ($3::text IS NOT NULL AND blg.generated_clickid = $3)
        )
    `, [row.bookmaker_id, row.imported_subid || null, row.imported_clickid || null]);

    for (const rec of tokenMatches.rows) {
      const existing = candidateMap.get(rec.id) || {
        account: rec,
        playerIdMatch: false,
        subidMatch: false,
        clickidMatch: false,
      };
      if (row.imported_subid && rec.generated_subid === row.imported_subid) existing.subidMatch = true;
      if (row.imported_clickid && rec.generated_clickid === row.imported_clickid) existing.clickidMatch = true;
      candidateMap.set(rec.id, existing);
    }
  }

  let createdOrUpdated = 0;
  for (const candidate of candidateMap.values()) {
    const registrationDateDiffDays = calcDateDiffDays(row.registration_date, candidate.account.created_at);
    const scoring = buildSuggestionScore({
      playerIdMatch: candidate.playerIdMatch,
      subidMatch: candidate.subidMatch,
      clickidMatch: candidate.clickidMatch,
      registrationDateDiffDays,
    });

    if (scoring.score <= 0) continue;

    await upsertPartnerMatchSuggestion(client, {
      bookmakerAccountId: candidate.account.id,
      partnerPlayerRowId: row.id,
      score: scoring.score,
      confidenceLevel: scoring.confidenceLevel,
      reasons: scoring.reasons,
      payload: {
        bookmaker_id: row.bookmaker_id,
        imported_player_id: row.imported_player_id || null,
        imported_subid: row.imported_subid || null,
        imported_clickid: row.imported_clickid || null,
        registration_date: row.registration_date || null,
        account_created_at: candidate.account.created_at || null,
        registration_date_diff_days: registrationDateDiffDays,
        matched_signals: {
          player_id: candidate.playerIdMatch,
          subid: candidate.subidMatch,
          clickid: candidate.clickidMatch,
        },
      },
    });
    createdOrUpdated += 1;
  }

  return createdOrUpdated;
}

// ---- BOOKMAKERS ----
app.get('/api/bookmakers', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, short_name, logo_url, rules, required_proofs, min_loss_rub,
             sort_order, cashback_label, offer_text, instruction_asset_url
      FROM bookmakers
      WHERE is_active = true
      ORDER BY sort_order, id
    `);
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/bookmakers/:id/generate-link', authMiddleware, async (req, res) => {
  try {
    await ensureUser(req.tgUser);
    const bookmakerId = parseInt(req.params.id);
    if (!Number.isInteger(bookmakerId) || bookmakerId <= 0) {
      return res.status(400).json({ error: 'Invalid bookmaker id' });
    }

    const bkRes = await pool.query('SELECT * FROM bookmakers WHERE id = $1 AND is_active = true', [bookmakerId]);
    if (!bkRes.rows.length) return res.status(404).json({ error: 'Bookmaker not found or disabled' });
    const bookmaker = bkRes.rows[0];

    if (!isValidTrackingMode(bookmaker.tracking_mode || 'none')) {
      return res.status(400).json({ error: 'Invalid tracking config for bookmaker' });
    }

    if (!bookmaker.affiliate_url_template) {
      return res.status(400).json({ error: 'Bookmaker link is not configured' });
    }

    let linkData;
    try {
      linkData = buildTrackedUrl(bookmaker, req.tgUser.id);
    } catch (e) {
      return res.status(400).json({ error: e.message || 'Cannot build tracked link' });
    }

    const insert = await pool.query(`
      INSERT INTO bookmaker_link_generations
        (user_id, bookmaker_id, affiliate_url_template_snapshot, tracking_mode, generated_subid, generated_clickid, final_url, generation_context, metadata_json)
      VALUES ($1,$2,$3,$4,$5,$6,$7,'miniapp_register_click',$8)
      RETURNING id, created_at
    `, [
      req.tgUser.id,
      bookmakerId,
      bookmaker.affiliate_url_template || null,
      linkData.trackingMode,
      linkData.generatedSubid,
      linkData.generatedClickid,
      linkData.finalUrl,
      JSON.stringify({ source: 'miniapp', user_id: req.tgUser.id })
    ]);

    res.json({
      success: true,
      bookmaker_id: bookmakerId,
      generation_id: insert.rows[0].id,
      created_at: insert.rows[0].created_at,
      final_url: linkData.finalUrl,
      warning: 'Регистрируйтесь только по этой ссылке. После регистрации понадобится player ID из профиля букмекера.',
    });
  } catch(e) {
    console.error('Generate link error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---- BOOKMAKER ACCOUNTS ----
app.post('/api/bookmaker-accounts', authMiddleware, async (req, res) => {
  try {
    const { bookmaker_id, affiliate_player_id } = req.body || {};
    const bookmakerId = parseInt(bookmaker_id);
    const playerId = String(affiliate_player_id || '').trim();

    if (!Number.isInteger(bookmakerId) || bookmakerId <= 0) {
      return res.status(400).json({ error: 'Invalid bookmaker_id' });
    }
    if (!playerId) {
      return res.status(400).json({ error: 'affiliate_player_id is required' });
    }

    await ensureUser(req.tgUser);

    const bkRes = await pool.query('SELECT id, name FROM bookmakers WHERE id=$1', [bookmakerId]);
    if (!bkRes.rows.length) return res.status(404).json({ error: 'Bookmaker not found' });

    const result = await pool.query(`
      INSERT INTO bookmaker_accounts (user_id, bookmaker_id, affiliate_player_id, status)
      VALUES ($1,$2,$3,'pending')
      ON CONFLICT (user_id, bookmaker_id) DO UPDATE SET
        affiliate_player_id = EXCLUDED.affiliate_player_id,
        status = 'pending',
        verified_at = NULL,
        rejected_at = NULL,
        rejection_reason = NULL,
        updated_at = NOW()
      RETURNING *
    `, [req.tgUser.id, bookmakerId, playerId]);

    res.json({ ...result.rows[0], bookmaker_name: bkRes.rows[0].name });
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/bookmaker-accounts', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ba.*, b.name as bookmaker_name, b.short_name, b.instruction_asset_url
      FROM bookmaker_accounts ba
      JOIN bookmakers b ON b.id = ba.bookmaker_id
      WHERE ba.user_id = $1
      ORDER BY ba.updated_at DESC
    `, [req.tgUser.id]);
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---- PAYOUT METHODS ----
app.get('/api/payout-methods', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM payout_methods WHERE user_id = $1 ORDER BY is_default DESC, created_at',
      [req.tgUser.id]
    );
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/payout-methods', authMiddleware, async (req, res) => {
  try {
    const { type, asset, address } = req.body;
    await ensureUser(req.tgUser);
    
    // Check if user changed address recently (anti-fraud: max once per 7 days)
    const recentChange = await pool.query(`
      SELECT id FROM payout_methods 
      WHERE user_id = $1 AND asset = $2 AND created_at > NOW() - INTERVAL '7 days'
      ORDER BY created_at DESC LIMIT 1
    `, [req.tgUser.id, asset]);
    
    // Count existing methods
    const count = await pool.query('SELECT COUNT(*) as cnt FROM payout_methods WHERE user_id=$1', [req.tgUser.id]);
    const isDefault = parseInt(count.rows[0].cnt) === 0;
    
    const result = await pool.query(`
      INSERT INTO payout_methods (user_id, type, asset, address, is_default)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING *
    `, [req.tgUser.id, type || 'external', asset, address, isDefault]);
    
    res.json(result.rows[0]);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/payout-requests', authMiddleware, async (req, res) => {
  try {
    const [listRes, minPayoutRub, summary] = await Promise.all([
      pool.query(`
        SELECT id, payout_method_id, amount_rub, asset, address_snapshot, status,
               admin_note, tx_hash, processed_at, created_at, updated_at
        FROM payout_requests
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 100
      `, [req.tgUser.id]),
      getSettingNumber('min_payout_amount_rub', 500),
      getUserWithdrawableSummary(req.tgUser.id),
    ]);

    res.json({
      requests: listRes.rows,
      min_payout_amount_rub: minPayoutRub,
      balance: summary,
      balance_rule: "available = SUM(claims.cashback_amount_rub where status='approved') - SUM(payout_requests.amount_rub where status in pending|approved|processing|paid)",
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/payout-requests', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const payoutMethodId = parseInt(req.body?.payout_method_id);
    const amountRub = parseFloat(req.body?.amount_rub);

    if (!Number.isInteger(payoutMethodId) || payoutMethodId <= 0) {
      return res.status(400).json({ error: 'Invalid payout_method_id' });
    }
    if (!Number.isFinite(amountRub) || amountRub <= 0) {
      return res.status(400).json({ error: 'Invalid amount_rub' });
    }

    await client.query('BEGIN');
    await ensureUser(req.tgUser);

    // Lightweight race guard: one payout-creation critical section per user per transaction.
    // Prevents concurrent requests from overspending the same available balance.
    await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [req.tgUser.id]);

    const methodRes = await client.query(`
      SELECT id, user_id, asset, address
      FROM payout_methods
      WHERE id = $1 AND user_id = $2
      LIMIT 1
    `, [payoutMethodId, req.tgUser.id]);
    if (!methodRes.rows.length) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Payout method not found for this user' });
    }

    const minPayoutRub = await getSettingNumber('min_payout_amount_rub', 500);
    if (amountRub < minPayoutRub) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Минимальная сумма выплаты: ${minPayoutRub} ₽` });
    }

    const summary = await getUserWithdrawableSummary(req.tgUser.id, client);
    if (amountRub > summary.available) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Недостаточно доступного баланса. Доступно: ${Math.floor(summary.available)} ₽` });
    }

    const method = methodRes.rows[0];
    const insert = await client.query(`
      INSERT INTO payout_requests
        (user_id, payout_method_id, amount_rub, asset, address_snapshot, status, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,'pending',NOW(),NOW())
      RETURNING *
    `, [req.tgUser.id, method.id, amountRub, method.asset, method.address]);

    await client.query('COMMIT');
    res.json({
      request: insert.rows[0],
      min_payout_amount_rub: minPayoutRub,
      balance_after: {
        approved_total: summary.approvedTotal,
        reserved_total: summary.reservedTotal + amountRub,
        available: Math.max(0, summary.available - amountRub),
      }
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: e.message || 'Server error' });
  } finally {
    client.release();
  }
});

// ---- REFERRAL ----
app.get('/api/referrals', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.first_name, u.username, u.created_at,
             COUNT(c.id) as claim_count,
             COALESCE(SUM(rl.amount_rub),0) as earned_from
      FROM users u
      LEFT JOIN claims c ON c.user_id = u.id AND c.status = 'paid'
      LEFT JOIN referral_ledger rl ON rl.referred_user_id = u.id AND rl.referrer_user_id = $1
      WHERE u.referrer_id = $1
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `, [req.tgUser.id]);
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// ADMIN ROUTES (protected by admin secret)
// ============================================================
const adminAuth = (req, res, next) => {
  const secret = req.headers['x-admin-secret'];
  if (secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  next();
};

const ALLOWED_NOTE_ENTITY_TYPES = new Set(['bookmaker_account', 'claim', 'payout_request']);

app.get('/admin/internal-notes', adminAuth, async (req, res) => {
  try {
    const entityType = String(req.query.entity_type || '').trim();
    const entityId = parseInt(req.query.entity_id);
    if (!ALLOWED_NOTE_ENTITY_TYPES.has(entityType)) {
      return res.status(400).json({ error: 'Invalid entity_type' });
    }
    if (!Number.isInteger(entityId) || entityId <= 0) {
      return res.status(400).json({ error: 'Invalid entity_id' });
    }

    const result = await pool.query(`
      SELECT id, entity_type, entity_id, note, is_private, created_by_admin_id, created_at
      FROM internal_notes
      WHERE entity_type = $1 AND entity_id = $2
      ORDER BY created_at DESC
      LIMIT 200
    `, [entityType, entityId]);

    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/admin/internal-notes', adminAuth, async (req, res) => {
  try {
    const entityType = String(req.body?.entity_type || '').trim();
    const entityId = parseInt(req.body?.entity_id);
    const note = String(req.body?.note || '').trim();
    const isPrivate = req.body?.is_private !== false;

    if (!ALLOWED_NOTE_ENTITY_TYPES.has(entityType)) {
      return res.status(400).json({ error: 'Invalid entity_type' });
    }
    if (!Number.isInteger(entityId) || entityId <= 0) {
      return res.status(400).json({ error: 'Invalid entity_id' });
    }
    if (!note) {
      return res.status(400).json({ error: 'note is required' });
    }
    if (note.length > 4000) {
      return res.status(400).json({ error: 'note is too long' });
    }

    const insert = await pool.query(`
      INSERT INTO internal_notes (entity_type, entity_id, note, is_private, created_by_admin_id, created_at)
      VALUES ($1,$2,$3,$4,$5,NOW())
      RETURNING *
    `, [entityType, entityId, note, isPrivate, 0]);

    await pool.query(`
      INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, payload_json)
      VALUES ($1, 'internal_note_created', $2, $3, $4)
    `, [0, entityType, entityId, JSON.stringify({ internal_note_id: insert.rows[0].id })]).catch(() => {});

    res.json(insert.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/bookmakers', adminAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bookmakers ORDER BY sort_order, id');
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/admin/bookmakers', adminAuth, async (req, res) => {
  try {
    const payload = req.body || {};
    const errors = validateBookmakerPayload(payload);
    if (errors.length) return res.status(400).json({ error: errors.join('; ') });

    const requiredProofs = Array.isArray(payload.required_proofs)
      ? payload.required_proofs.filter(Boolean)
      : String(payload.required_proofs || '').split(',').map(v => v.trim()).filter(Boolean);

    const result = await pool.query(`
      INSERT INTO bookmakers
        (name, short_name, logo_url, rules, required_proofs, min_loss_rub, is_active, sort_order,
         affiliate_url_template, tracking_mode, tracking_subid_param, tracking_clickid_param,
         offer_text, cashback_label, instruction_asset_url, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW(),NOW())
      RETURNING *
    `, [
      String(payload.name || '').trim(),
      payload.short_name || null,
      payload.logo_url || null,
      payload.rules || null,
      requiredProofs,
      parseInt(payload.min_loss_rub) || 500,
      payload.is_active !== false,
      parseInt(payload.sort_order) || 0,
      (payload.affiliate_url_template || '').trim() || null,
      payload.tracking_mode || 'none',
      sanitizeParamName(payload.tracking_subid_param, 'subid') || 'subid',
      sanitizeParamName(payload.tracking_clickid_param, 'clickid') || 'clickid',
      payload.offer_text || null,
      payload.cashback_label || null,
      payload.instruction_asset_url || null,
    ]);

    await pool.query(`
      INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, payload_json)
      VALUES ($1, 'bookmaker_created', 'bookmaker', $2, $3)
    `, [0, result.rows[0].id, JSON.stringify({ name: result.rows[0].name })]).catch(() => {});

    res.json(result.rows[0]);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/admin/bookmakers/:id', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

    const currentRes = await pool.query('SELECT * FROM bookmakers WHERE id = $1', [id]);
    if (!currentRes.rows.length) return res.status(404).json({ error: 'Not found' });

    const payload = { ...currentRes.rows[0], ...(req.body || {}) };
    const errors = validateBookmakerPayload(payload);
    if (errors.length) return res.status(400).json({ error: errors.join('; ') });

    const requiredProofs = Array.isArray(payload.required_proofs)
      ? payload.required_proofs.filter(Boolean)
      : String(payload.required_proofs || '').split(',').map(v => v.trim()).filter(Boolean);

    const result = await pool.query(`
      UPDATE bookmakers SET
        name=$1, short_name=$2, logo_url=$3, rules=$4, required_proofs=$5, min_loss_rub=$6,
        is_active=$7, sort_order=$8, affiliate_url_template=$9, tracking_mode=$10,
        tracking_subid_param=$11, tracking_clickid_param=$12, offer_text=$13,
        cashback_label=$14, instruction_asset_url=$15, updated_at=NOW()
      WHERE id=$16
      RETURNING *
    `, [
      String(payload.name || '').trim(),
      payload.short_name || null,
      payload.logo_url || null,
      payload.rules || null,
      requiredProofs,
      parseInt(payload.min_loss_rub) || 500,
      payload.is_active !== false,
      parseInt(payload.sort_order) || 0,
      (payload.affiliate_url_template || '').trim() || null,
      payload.tracking_mode || 'none',
      sanitizeParamName(payload.tracking_subid_param, 'subid') || 'subid',
      sanitizeParamName(payload.tracking_clickid_param, 'clickid') || 'clickid',
      payload.offer_text || null,
      payload.cashback_label || null,
      payload.instruction_asset_url || null,
      id,
    ]);

    await pool.query(`
      INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, payload_json)
      VALUES ($1, 'bookmaker_updated', 'bookmaker', $2, $3)
    `, [0, id, JSON.stringify({ name: result.rows[0].name })]).catch(() => {});

    res.json(result.rows[0]);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/bookmaker-accounts', adminAuth, async (req, res) => {
  try {
    const { status } = req.query;
    const params = [];
    let where = '';
    if (status && ['pending','verified','rejected'].includes(status)) {
      params.push(status);
      where = `WHERE ba.status = $${params.length}`;
    }

    const result = await pool.query(`
      SELECT ba.id, ba.user_id, ba.bookmaker_id, ba.affiliate_player_id, ba.status,
             ba.created_at, ba.updated_at, ba.rejection_reason,
             u.first_name, u.username,
             b.name as bookmaker_name,
             sel.selected_suggestion_id, sel.selected_confidence_level, sel.selected_confidence_score,
             sel.selected_reasons, sel.selected_imported_player_id, sel.selected_imported_subid, sel.selected_imported_clickid
      FROM bookmaker_accounts ba
      JOIN users u ON u.id = ba.user_id
      JOIN bookmakers b ON b.id = ba.bookmaker_id
      LEFT JOIN LATERAL (
        SELECT pms.id as selected_suggestion_id,
               pms.confidence_level as selected_confidence_level,
               pms.confidence_score as selected_confidence_score,
               pms.reasons as selected_reasons,
               ppr.imported_player_id as selected_imported_player_id,
               ppr.imported_subid as selected_imported_subid,
               ppr.imported_clickid as selected_imported_clickid
        FROM partner_match_suggestions pms
        JOIN partner_player_rows ppr ON ppr.id = pms.partner_player_row_id
        WHERE pms.bookmaker_account_id = ba.id AND pms.is_selected = TRUE
        ORDER BY pms.selected_at DESC NULLS LAST, pms.id DESC
        LIMIT 1
      ) sel ON TRUE
      ${where}
      ORDER BY CASE WHEN ba.status='pending' THEN 0 ELSE 1 END, ba.updated_at DESC
      LIMIT 300
    `, params);
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/payout-requests', adminAuth, async (req, res) => {
  try {
    const { status } = req.query;
    const params = [];
    let where = '';
    if (status && ['pending', 'approved', 'rejected', 'processing', 'paid', 'failed'].includes(status)) {
      params.push(status);
      where = `WHERE pr.status = $${params.length}`;
    }

    const result = await pool.query(`
      SELECT pr.*, u.first_name, u.username
      FROM payout_requests pr
      JOIN users u ON u.id = pr.user_id
      ${where}
      ORDER BY CASE WHEN pr.status='pending' THEN 0 WHEN pr.status='processing' THEN 1 ELSE 2 END,
               pr.created_at DESC
      LIMIT 500
    `, params);

    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/admin/payout-requests/:id/status', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { status, admin_note, tx_hash } = req.body || {};
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

    const allowed = ['pending', 'approved', 'rejected', 'processing', 'paid', 'failed'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    if (status === 'paid' && !String(tx_hash || '').trim()) {
      return res.status(400).json({ error: 'tx_hash is required when marking as paid' });
    }

    const currentRes = await pool.query('SELECT * FROM payout_requests WHERE id = $1', [id]);
    if (!currentRes.rows.length) return res.status(404).json({ error: 'Not found' });
    const current = currentRes.rows[0];

    const transitions = {
      pending: ['approved', 'rejected', 'processing', 'failed'],
      approved: ['processing', 'paid', 'failed', 'rejected'],
      processing: ['paid', 'failed', 'rejected'],
      paid: [],
      rejected: [],
      failed: [],
    };

    if (!transitions[current.status]?.includes(status)) {
      return res.status(400).json({ error: `Invalid transition: ${current.status} -> ${status}` });
    }

    const result = await pool.query(`
      UPDATE payout_requests
      SET status = $1,
          admin_note = COALESCE($2, admin_note),
          tx_hash = CASE WHEN $3::text IS NULL OR $3::text = '' THEN tx_hash ELSE $3 END,
          processed_by_admin_id = 0,
          processed_at = CASE WHEN $1 IN ('approved','rejected','processing','paid','failed') THEN NOW() ELSE processed_at END,
          updated_at = NOW()
      WHERE id = $4
      RETURNING *
    `, [status, admin_note || null, tx_hash || null, id]);

    await pool.query(`
      INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, payload_json)
      VALUES ($1, $2, 'payout_request', $3, $4)
    `, [0, `payout_request_${status}`, id, JSON.stringify({ admin_note: admin_note || null, tx_hash: tx_hash || null })]).catch(() => {});

    // Best-effort user notification (must not break business action on Telegram failure)
    const updated = result.rows[0];
    const payoutMsgs = {
      approved: `💸 Запрос на вывод #${id} одобрен. Готовим выплату.`,
      processing: `⏳ Запрос на вывод #${id} в обработке. Скоро отправим перевод.`,
      paid: `✅ Выплата по запросу #${id} отправлена${updated.tx_hash ? `\nTX: ${updated.tx_hash}` : ''}.`,
      rejected: `❌ Запрос на вывод #${id} отклонён.${updated.admin_note ? `\nПричина: ${updated.admin_note}` : ''}`,
      failed: `⚠️ Выплата по запросу #${id} не выполнена.${updated.admin_note ? `\nПричина: ${updated.admin_note}` : ''}`,
    };
    if (payoutMsgs[status]) {
      await sendUserNotificationSafe(updated.user_id, payoutMsgs[status]);
    }

    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/admin/bookmaker-accounts/:id/status', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { status, rejection_reason } = req.body || {};
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });
    if (!['pending','verified','rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await pool.query(`
      UPDATE bookmaker_accounts
      SET status = $1,
          verification_source = CASE WHEN $1='verified' THEN 'manual' ELSE verification_source END,
          verified_at = CASE WHEN $1='verified' THEN NOW() ELSE NULL END,
          rejected_at = CASE WHEN $1='rejected' THEN NOW() ELSE NULL END,
          rejection_reason = CASE WHEN $1='rejected' THEN $2 ELSE NULL END,
          verified_by_admin_id = CASE WHEN $1='verified' THEN 0 ELSE verified_by_admin_id END,
          updated_at = NOW()
      WHERE id = $3
      RETURNING *
    `, [status, rejection_reason || null, id]);

    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

    await pool.query(`
      INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, payload_json)
      VALUES ($1, $2, 'bookmaker_account', $3, $4)
    `, [0, `bookmaker_account_${status}`, id, JSON.stringify({ rejection_reason: rejection_reason || null })]).catch(() => {});

    // Best-effort user notification (verified/rejected only)
    if (status === 'verified') {
      await sendUserNotificationSafe(result.rows[0].user_id,
        `✅ Ваш аккаунт букмекера подтверждён.\nТеперь можно отправлять заявки на кэшбэк.`
      );
    }
    if (status === 'rejected') {
      await sendUserNotificationSafe(result.rows[0].user_id,
        `❌ Player ID букмекера отклонён.${rejection_reason ? `\nПричина: ${rejection_reason}` : ''}\nПроверьте ID и отправьте заново.`
      );
    }

    res.json(result.rows[0]);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


app.get('/admin/partner-imports', adminAuth, async (req, res) => {
  try {
    const { bookmaker_id } = req.query;
    const params = [];
    let where = '';
    if (bookmaker_id && Number.isInteger(parseInt(bookmaker_id))) {
      params.push(parseInt(bookmaker_id));
      where = `WHERE pib.bookmaker_id = $${params.length}`;
    }

    const result = await pool.query(`
      SELECT pib.*, b.name as bookmaker_name,
             COALESCE(ms.suggestions_count, 0) as suggestions_count
      FROM partner_import_batches pib
      JOIN bookmakers b ON b.id = pib.bookmaker_id
      LEFT JOIN (
        SELECT ppr.batch_id, COUNT(*)::int as suggestions_count
        FROM partner_match_suggestions pms
        JOIN partner_player_rows ppr ON ppr.id = pms.partner_player_row_id
        GROUP BY ppr.batch_id
      ) ms ON ms.batch_id = pib.id
      ${where}
      ORDER BY pib.created_at DESC
      LIMIT 100
    `, params);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/partner-imports/:id', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

    const batchRes = await pool.query(`
      SELECT pib.*, b.name as bookmaker_name
      FROM partner_import_batches pib
      JOIN bookmakers b ON b.id = pib.bookmaker_id
      WHERE pib.id = $1
    `, [id]);
    if (!batchRes.rows.length) return res.status(404).json({ error: 'Not found' });

    const rowsRes = await pool.query(`
      SELECT id, imported_player_id, imported_subid, imported_clickid, registration_date,
             last_activity_at, total_deposit_rub, total_ggr_rub, is_diff_new, is_diff_changed, created_at
      FROM partner_player_rows
      WHERE batch_id = $1
      ORDER BY id ASC
      LIMIT 500
    `, [id]);

    res.json({ batch: batchRes.rows[0], rows: rowsRes.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/partner-imports/:id/suggestions', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

    const result = await pool.query(`
      SELECT pms.id, pms.bookmaker_account_id, pms.partner_player_row_id,
             pms.confidence_score, pms.confidence_level, pms.reasons,
             pms.suggestion_payload_json, pms.is_selected, pms.selected_at,
             ba.user_id, ba.bookmaker_id, ba.affiliate_player_id, ba.status as bookmaker_account_status,
             u.first_name, u.username,
             b.name as bookmaker_name,
             ppr.imported_player_id, ppr.imported_subid, ppr.imported_clickid,
             ppr.registration_date, ppr.last_activity_at,
             ppr.total_deposit_rub, ppr.total_ggr_rub
      FROM partner_match_suggestions pms
      JOIN partner_player_rows ppr ON ppr.id = pms.partner_player_row_id
      JOIN bookmaker_accounts ba ON ba.id = pms.bookmaker_account_id
      LEFT JOIN users u ON u.id = ba.user_id
      JOIN bookmakers b ON b.id = ba.bookmaker_id
      WHERE ppr.batch_id = $1
      ORDER BY
        CASE pms.confidence_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
        pms.confidence_score DESC,
        pms.id DESC
      LIMIT 1000
    `, [id]);

    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/bookmaker-accounts/:id/suggestions', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

    const result = await pool.query(`
      SELECT pms.id, pms.bookmaker_account_id, pms.partner_player_row_id,
             pms.confidence_score, pms.confidence_level, pms.reasons,
             pms.suggestion_payload_json, pms.is_selected, pms.selected_at,
             ppr.batch_id, ppr.imported_player_id, ppr.imported_subid, ppr.imported_clickid,
             ppr.registration_date, ppr.last_activity_at,
             ppr.total_deposit_rub, ppr.total_ggr_rub,
             pib.original_filename, pib.created_at as batch_created_at,
             b.name as bookmaker_name,
             ba.user_id,
             u.first_name,
             u.username
      FROM partner_match_suggestions pms
      JOIN partner_player_rows ppr ON ppr.id = pms.partner_player_row_id
      JOIN partner_import_batches pib ON pib.id = ppr.batch_id
      JOIN bookmaker_accounts ba ON ba.id = pms.bookmaker_account_id
      LEFT JOIN users u ON u.id = ba.user_id
      JOIN bookmakers b ON b.id = ppr.bookmaker_id
      WHERE pms.bookmaker_account_id = $1
      ORDER BY
        CASE pms.confidence_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
        pms.confidence_score DESC,
        pms.id DESC
      LIMIT 100
    `, [id]);

    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/admin/partner-match-suggestions/:id/select', adminAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const id = parseInt(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });

    await client.query('BEGIN');

    const found = await client.query('SELECT * FROM partner_match_suggestions WHERE id = $1', [id]);
    if (!found.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Suggestion not found' });
    }
    const suggestion = found.rows[0];

    await client.query(`
      UPDATE partner_match_suggestions
      SET is_selected = FALSE,
          selected_by_admin_id = NULL,
          selected_at = NULL
      WHERE bookmaker_account_id = $1
    `, [suggestion.bookmaker_account_id]);

    const update = await client.query(`
      UPDATE partner_match_suggestions
      SET is_selected = TRUE,
          selected_by_admin_id = 0,
          selected_at = NOW()
      WHERE id = $1
      RETURNING *
    `, [id]);

    await client.query(`
      INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, payload_json)
      VALUES ($1, 'partner_match_suggestion_selected', 'partner_match_suggestion', $2, $3)
    `, [0, id, JSON.stringify({ bookmaker_account_id: suggestion.bookmaker_account_id, partner_player_row_id: suggestion.partner_player_row_id })]).catch(() => {});

    await client.query('COMMIT');
    res.json(update.rows[0]);
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.post('/admin/partner-imports', adminAuth, partnerImportUpload.single('file'), async (req, res) => {
  const client = await pool.connect();
  try {
    const bookmakerId = parseInt(req.body?.bookmaker_id);
    if (!Number.isInteger(bookmakerId) || bookmakerId <= 0) {
      return res.status(400).json({ error: 'Invalid bookmaker_id' });
    }
    if (!req.file) return res.status(400).json({ error: 'Import file is required' });

    const bookmakerRes = await client.query('SELECT * FROM bookmakers WHERE id = $1', [bookmakerId]);
    if (!bookmakerRes.rows.length) return res.status(404).json({ error: 'Bookmaker not found' });
    const bookmaker = bookmakerRes.rows[0];

    const parser = getBookmakerParser(bookmaker);
    const parsedRows = parser(req.file.buffer);
    if (!parsedRows.length) return res.status(400).json({ error: 'No rows parsed from file' });

    const checksum = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

    await client.query('BEGIN');

    const batchRes = await client.query(`
      INSERT INTO partner_import_batches
        (bookmaker_id, uploaded_by_admin_id, source_name, original_filename, file_checksum, status, rows_total, created_at)
      VALUES ($1, $2, 'csv_upload', $3, $4, 'uploaded', $5, NOW())
      RETURNING *
    `, [bookmakerId, 0, req.file.originalname || 'import.csv', checksum, parsedRows.length]);
    const batch = batchRes.rows[0];

    const prevBatchRes = await client.query(`
      SELECT id FROM partner_import_batches
      WHERE bookmaker_id = $1 AND id <> $2 AND status = 'processed'
      ORDER BY created_at DESC
      LIMIT 1
    `, [bookmakerId, batch.id]);

    const prevByKey = new Map();
    if (prevBatchRes.rows.length) {
      const prevRows = await client.query(`
        SELECT * FROM partner_player_rows WHERE batch_id = $1
      `, [prevBatchRes.rows[0].id]);
      for (const r of prevRows.rows) prevByKey.set(buildDiffKey(r), r);
    }

    let rowsNew = 0;
    let rowsChanged = 0;
    let rowsUnchanged = 0;

    const insertedRows = [];
    for (const row of parsedRows) {
      const key = buildDiffKey(row);
      const prev = prevByKey.get(key);
      const isNew = !prev;
      const isChanged = !!prev && isRowChanged(prev, row);

      if (isNew) rowsNew += 1;
      else if (isChanged) rowsChanged += 1;
      else rowsUnchanged += 1;

      const insertRow = await client.query(`
        INSERT INTO partner_player_rows
          (batch_id, bookmaker_id, external_row_id, imported_player_id, imported_subid, imported_clickid,
           registration_date, last_activity_at, total_deposit_rub, total_ggr_rub, raw_payload_json,
           is_diff_new, is_diff_changed, prev_row_id, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW())
      RETURNING id, bookmaker_id, imported_player_id, imported_subid, imported_clickid, registration_date
      `, [
        batch.id,
        bookmakerId,
        row.external_row_id || null,
        row.imported_player_id || null,
        row.imported_subid || null,
        row.imported_clickid || null,
        row.registration_date,
        row.last_activity_at,
        row.total_deposit_rub,
        row.total_ggr_rub,
        JSON.stringify(row.raw_payload_json || {}),
        isNew,
        isChanged,
        prev?.id || null,
      ]);
      if (insertRow.rows[0]) insertedRows.push(insertRow.rows[0]);
    }

    let suggestionsUpserted = 0;
    for (const insertedRow of insertedRows) {
      suggestionsUpserted += await generateSuggestionsForImportedRow(client, insertedRow);
    }

    const update = await client.query(`
      UPDATE partner_import_batches
      SET status = 'processed', rows_total = $1, rows_new = $2, rows_changed = $3, rows_unchanged = $4, processed_at = NOW()
      WHERE id = $5
      RETURNING *
    `, [parsedRows.length, rowsNew, rowsChanged, rowsUnchanged, batch.id]);

    await client.query(`
      INSERT INTO admin_audit_log (admin_id, action, entity_type, entity_id, payload_json)
      VALUES ($1, 'partner_import_uploaded', 'partner_import_batch', $2, $3)
    `, [0, batch.id, JSON.stringify({ bookmaker_id: bookmakerId, filename: req.file.originalname })]).catch(() => {});

    await client.query('COMMIT');

    res.json({
      success: true,
      batch: update.rows[0],
      summary: {
        rows_total: parsedRows.length,
        rows_new: rowsNew,
        rows_changed: rowsChanged,
        rows_unchanged: rowsUnchanged,
        suggestions_upserted: suggestionsUpserted,
      }
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Partner import error:', e);
    res.status(500).json({ error: e.message || 'Import failed' });
  } finally {
    client.release();
  }
});

app.get('/admin/claims', adminAuth, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const offset = (pageNum - 1) * limitNum;

    const params = [];
    let whereClause = '';
    if (status) {
      params.push(status);
      whereClause = `WHERE c.status = $${params.length}`;
    }

    params.push(limitNum);
    const limitParam = `$${params.length}`;
    params.push(offset);
    const offsetParam = `$${params.length}`;

    const result = await pool.query(`
      SELECT c.*, b.name as bookmaker_name,
             u.first_name, u.username,
             json_agg(json_build_object('url', ca.file_url, 'hash', ca.file_hash, 'is_dup', ca.is_duplicate)) as attachments
      FROM claims c
      JOIN bookmakers b ON b.id = c.bookmaker_id
      JOIN users u ON u.id = c.user_id
      LEFT JOIN claim_attachments ca ON ca.claim_id = c.id
      ${whereClause}
      GROUP BY c.id, b.name, u.first_name, u.username
      ORDER BY c.created_at DESC
      LIMIT ${limitParam} OFFSET ${offsetParam}
    `, params);
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/admin/claims/:id', adminAuth, async (req, res) => {
  try {
    const { status, admin_note, tx_hash } = req.body;
    const { id } = req.params;
    
    const allowed = ['in_review','approved','rejected','paid'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });
    
    const result = await pool.query(`
      UPDATE claims SET status=$1, admin_note=$2, tx_hash=$3, updated_at=NOW()
      WHERE id=$4 RETURNING *, (SELECT name FROM bookmakers WHERE id=bookmaker_id) as bk_name
    `, [status, admin_note || null, tx_hash || null, id]);
    
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const claim = result.rows[0];
    
    // Process referral commission on approval
    if (status === 'approved') {
      await processReferralCommission(claim);
    }
    
    // Audit log
    await pool.query(`
      INSERT INTO audit_log (actor_type, actor_id, action, entity, entity_id, payload_json)
      VALUES ('admin', 0, $1, 'claim', $2, $3)
    `, [`claim_${status}`, id, JSON.stringify({ note: admin_note, tx_hash })]);
    
    // Notify user
    const msgs = {
      in_review: `🔍 Заявка #${id} взята в работу. Проверяем...`,
      approved: `✅ Заявка #${id} одобрена.\n💰 Кэшбэк: ${claim.cashback_amount_rub}₽.`,
      rejected: `❌ Заявка #${id} отклонена.${admin_note ? `\nПричина: ${admin_note}` : ''}`,
      paid: `💸 Выплата по заявке #${id} отправлена.${tx_hash ? `\nTX: ${tx_hash}` : ''}`,
    };
    if (msgs[status]) await sendUserNotificationSafe(claim.user_id, msgs[status]);
    
    res.json(claim);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/users', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.*,
        COUNT(DISTINCT c.id) as claim_count,
        COALESCE(SUM(CASE WHEN c.status='paid' THEN c.cashback_amount_rub ELSE 0 END),0) as total_paid
      FROM users u
      LEFT JOIN claims c ON c.user_id = u.id
      GROUP BY u.id ORDER BY u.created_at DESC LIMIT 100
    `);
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const [users, claims, payouts] = await Promise.all([
      pool.query('SELECT COUNT(*) as total FROM users'),
      pool.query(`SELECT status, COUNT(*) as cnt, COALESCE(SUM(cashback_amount_rub),0) as amount FROM claims GROUP BY status`),
      pool.query(`SELECT COALESCE(SUM(cashback_amount_rub),0) as total_paid FROM claims WHERE status='paid'`),
    ]);
    res.json({
      users: users.rows[0],
      claims: claims.rows,
      payouts: payouts.rows[0],
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/admin/export/claims', adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.id, c.status, c.loss_amount_rub, c.cashback_amount_rub, c.cashback_percent,
             c.bet_id, c.bet_date, c.risk_score, c.admin_note, c.tx_hash, c.created_at,
             b.name as bookmaker, u.first_name, u.username
      FROM claims c
      JOIN bookmakers b ON b.id = c.bookmaker_id
      JOIN users u ON u.id = c.user_id
      ORDER BY c.created_at DESC
    `);
    
    const header = Object.keys(result.rows[0] || {}).join(',');
    const rows = result.rows.map(r => Object.values(r).map(v => `"${String(v).replace(/"/g,'""')}"`).join(','));
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=claims.csv');
    res.send([header, ...rows].join('\n'));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- BROADCAST ----
app.post('/admin/broadcast', adminAuth, async (req, res) => {
  try {
    const { message, filter } = req.body; // filter: 'all' | 'active' | 'inactive'
    let query = 'SELECT id FROM users';
    if (filter === 'active') query += ` WHERE id IN (SELECT DISTINCT user_id FROM claims WHERE created_at > NOW() - INTERVAL '30 days')`;
    if (filter === 'inactive') query += ` WHERE id NOT IN (SELECT DISTINCT user_id FROM claims WHERE created_at > NOW() - INTERVAL '30 days')`;
    
    const users = await pool.query(query);
    let sent = 0, failed = 0;
    
    for (const u of users.rows) {
      try {
        await bot.sendMessage(u.id, message, { parse_mode: 'HTML' });
        sent++;
        await new Promise(r => setTimeout(r, 50)); // Rate limit
      } catch { failed++; }
    }
    
    res.json({ sent, failed, total: users.rows.length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// REFERRAL COMMISSION LOGIC
// ============================================================
async function processReferralCommission(claim) {
  try {
    // Get referrer (L1)
    const l1 = await pool.query('SELECT referrer_id FROM users WHERE id = $1', [claim.user_id]);
    if (!l1.rows[0]?.referrer_id) return;
    
    const l1Id = l1.rows[0].referrer_id;
    const l1Amount = claim.cashback_amount_rub * 0.20;
    
    await pool.query(`
      INSERT INTO referral_ledger (referrer_user_id, referred_user_id, claim_id, level, amount_rub, status)
      VALUES ($1,$2,$3,1,$4,'pending')
      ON CONFLICT DO NOTHING
    `, [l1Id, claim.user_id, claim.id, l1Amount]);
    
    // Notify L1
    bot.sendMessage(l1Id, 
      `💰 +${l1Amount.toFixed(0)}₽ реф. бонус!\n@${claim.username || claim.user_id} получил кэшбэк`
    ).catch(() => {});
    
    // Get L2 referrer
    const l2 = await pool.query('SELECT referrer_id FROM users WHERE id = $1', [l1Id]);
    if (!l2.rows[0]?.referrer_id) return;
    
    const l2Id = l2.rows[0].referrer_id;
    const l2Amount = claim.cashback_amount_rub * 0.05;
    
    await pool.query(`
      INSERT INTO referral_ledger (referrer_user_id, referred_user_id, claim_id, level, amount_rub, status)
      VALUES ($1,$2,$3,2,$4,'pending')
      ON CONFLICT DO NOTHING
    `, [l2Id, claim.user_id, claim.id, l2Amount]);
  } catch(e) {
    console.error('Referral error:', e);
  }
}

// ============================================================
// BOT WEBHOOK / COMMANDS
// ============================================================
app.post('/webhook', async (req, res) => {
  try {
    const update = req.body;
    if (update.message) {
      const msg = update.message;
      const text = msg.text || '';
      const chatId = msg.chat.id;
      
      if (text.startsWith('/start')) {
        const ref = text.split(' ')[1] || null;
        // Save referral
        if (ref?.startsWith('ref_')) {
          const refId = parseInt(ref.replace('ref_', ''));
          if (refId && refId !== chatId) {
            await pool.query(
              'UPDATE users SET referrer_id = $1 WHERE id = $2 AND referrer_id IS NULL',
              [refId, chatId]
            ).catch(() => {});
          }
        }
        
        await bot.sendMessage(chatId, 
          `🎯 Добро пожаловать в BetCashback!\n\n` +
          `Получайте кэшбэк 5-10% за проигрыши у букмекеров в крипте.\n\n` +
          `👇 Открыть приложение:`,
          {
            reply_markup: {
              inline_keyboard: [[{
                text: '🚀 Открыть BetCashback',
                web_app: { url: process.env.FRONTEND_URL }
              }]]
            }
          }
        );
      }
    }
    res.json({ ok: true });
  } catch(e) {
    console.error('Webhook error:', e);
    res.json({ ok: true });
  }
});

// ============================================================
// START
// ============================================================
app.listen(PORT, async () => {
  console.log(`🚀 BetCashback server running on port ${PORT}`);
  try {
    await pool.query('SELECT 1');
    console.log('✅ Database connected');
  } catch(e) {
    console.error('❌ Database connection failed:', e.message);
  }
  
  // Set webhook if URL is configured
  if (process.env.BACKEND_URL && process.env.BOT_TOKEN) {
    bot.setWebHook(`${process.env.BACKEND_URL}/webhook`).then(() => {
      console.log('✅ Telegram webhook set');
    }).catch(e => console.error('Webhook error:', e.message));
  }
});
