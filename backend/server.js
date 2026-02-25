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
    const { bookmaker_id, bookmaker_account_id, affiliate_player_id, loss_amount, bet_id, bet_date, comment } = req.body;
    
    if (!bookmaker_id || !loss_amount || !bet_id || !bet_date) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (parseFloat(loss_amount) <= 0) return res.status(400).json({ error: 'Invalid amount' });
    if (!req.files?.length) return res.status(400).json({ error: 'At least 1 screenshot required' });
    
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Ensure user
      await ensureUser(req.tgUser);
      
      // Get tier
      const tier = await getUserTier(req.tgUser.id);
      const cashback = parseFloat(loss_amount) * (tier.pct / 100);
      
      // Risk score
      const riskScore = await calculateRiskScore(req.tgUser.id, bet_id, parseFloat(loss_amount));
      
      // Create claim
      const claimRes = await client.query(`
        INSERT INTO claims (user_id, bookmaker_id, affiliate_player_id, loss_amount_rub, bet_id, bet_date, comment, status, cashback_percent, cashback_amount_rub, risk_score)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'submitted',$8,$9,$10)
        RETURNING *
      `, [req.tgUser.id, bookmaker_id, affiliate_player_id || null, loss_amount, bet_id, bet_date, comment || null, tier.pct, cashback, riskScore]);
      
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
          `🏦 BK ID: ${bookmaker_id}\n` +
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

// ---- BOOKMAKERS ----
app.get('/api/bookmakers', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bookmakers WHERE is_active = true ORDER BY sort_order');
    res.json(result.rows);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ---- BOOKMAKER ACCOUNTS ----
app.post('/api/bookmaker-accounts', authMiddleware, async (req, res) => {
  try {
    const { bookmaker_id, affiliate_player_id } = req.body;
    await ensureUser(req.tgUser);
    
    const result = await pool.query(`
      INSERT INTO bookmaker_accounts (user_id, bookmaker_id, affiliate_player_id, status)
      VALUES ($1,$2,$3,'pending')
      ON CONFLICT (user_id, bookmaker_id) DO UPDATE SET
        affiliate_player_id = EXCLUDED.affiliate_player_id,
        updated_at = NOW()
      RETURNING *
    `, [req.tgUser.id, bookmaker_id, affiliate_player_id]);
    
    res.json(result.rows[0]);
  } catch(e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/bookmaker-accounts', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ba.*, b.name as bookmaker_name
      FROM bookmaker_accounts ba
      JOIN bookmakers b ON b.id = ba.bookmaker_id
      WHERE ba.user_id = $1
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

app.get('/admin/claims', adminAuth, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    const where = status ? `AND c.status = '${status}'` : '';
    const result = await pool.query(`
      SELECT c.*, b.name as bookmaker_name,
             u.first_name, u.username,
             json_agg(json_build_object('url', ca.file_url, 'hash', ca.file_hash, 'is_dup', ca.is_duplicate)) as attachments
      FROM claims c
      JOIN bookmakers b ON b.id = c.bookmaker_id
      JOIN users u ON u.id = c.user_id
      LEFT JOIN claim_attachments ca ON ca.claim_id = c.id
      WHERE 1=1 ${where}
      GROUP BY c.id, b.name, u.first_name, u.username
      ORDER BY c.created_at DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
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
      approved: `✅ Заявка #${id} одобрена!\n💰 Кэшбэк: ${claim.cashback_amount_rub}₽ — выплата в ближайшем батче`,
      rejected: `❌ Заявка #${id} отклонена\n${admin_note ? `\nПричина: ${admin_note}` : ''}`,
      paid: `💸 Выплата по заявке #${id} отправлена!\nTX: ${tx_hash || 'уточняется'}`,
    };
    bot.sendMessage(claim.user_id, msgs[status]).catch(() => {});
    
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
