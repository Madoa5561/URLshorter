import { Hono, Context } from 'hono';
import { cors } from 'hono/cors';
import { Bindings, UrlMappingRow, AccessLogRow } from './types';
import { fetchMeta } from './ogp';
import { generateToken, verifyToken } from './auth';
import { renderRedirect } from './templates/redirect';
import { renderExpired } from './templates/expired';
import { renderError } from './templates/error';

const app = new Hono<{ Bindings: Bindings }>();

// ======== CORS ミドルウェア ========
app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    exposeHeaders: ['Content-Type'],
  })
);

// ======== セキュリティヘッダー & レート制限 ========
const rateLimitMap = new Map<string, number[]>();
const RATE_LIMIT = 75; // 1分あたり75リクエスト

app.use('*', async (c, next) => {
  // レート制限チェック
  const ip =
    c.req.header('cf-connecting-ip') ||
    c.req.header('x-forwarded-for') ||
    '127.0.0.1';
  const now = Date.now();
  let timestamps = rateLimitMap.get(ip) || [];
  timestamps = timestamps.filter((t) => now - t < 60000);
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);

  if (timestamps.length > RATE_LIMIT) {
    c.header('Retry-After', '60');
    return c.json(
      {
        error: 'レート制限を超えました。しばらく待ってから再試行してください。',
        retry_after: '60秒',
      },
      429
    );
  }

  await next();

  // セキュリティヘッダー設定
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

// ======== ヘルパー関数 ========

function getBaseUrl(c: Context<{ Bindings: Bindings }>): string {
  if (c.env.BASE_URL) {
    return c.env.BASE_URL.replace(/\/+$/, '');
  }
  return new URL(c.req.url).origin;
}

async function addLog(
  db: D1Database,
  type: string,
  message: string,
  details: string | null = null
): Promise<void> {
  try {
    await db
      .prepare('INSERT INTO access_logs (type, message, details) VALUES (?, ?, ?)')
      .bind(type, message, details)
      .run();
  } catch (err) {
    console.error('Error adding log:', err);
  }
}

function isValidUrl(urlString: string): boolean {
  try {
    if (!urlString || typeof urlString !== 'string') return false;
    if (urlString.length < 3 || urlString.length > 2000) return false;

    // 危険文字チェック
    const dangerousChars = ['<', '>', '{', '}', '|'];
    if (dangerousChars.some((char) => urlString.includes(char))) {
      return false;
    }

    const parsed = new URL(urlString);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    if (!parsed.hostname) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function generateRandomString(length = 6): string {
  // 見間違いを防ぐ文字セット (Il1O0o を除外)
  const safeLetters = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  const safeChars = safeLetters + '23456789';

  // 1文字目は必ず英字
  let result = safeLetters.charAt(Math.floor(Math.random() * safeLetters.length));
  for (let i = 1; i < length; i++) {
    result += safeChars.charAt(Math.floor(Math.random() * safeChars.length));
  }
  return result;
}

async function generateUniqueShortened(db: D1Database): Promise<string> {
  let attempts = 0;
  while (attempts < 20) {
    const candidate = generateRandomString(6);
    const existing = await db
      .prepare('SELECT shortened FROM url_mapping WHERE shortened = ?')
      .bind(candidate)
      .first();
    if (!existing) {
      return candidate;
    }
    attempts++;
  }
  throw new Error('短縮文字列の生成に失敗しました');
}

async function cleanupOldData(db: D1Database): Promise<void> {
  try {
    await db
      .prepare("DELETE FROM access_logs WHERE timestamp < datetime('now', '-30 days')")
      .run();
    await db
      .prepare(
        "DELETE FROM url_mapping WHERE access_count = 0 AND created_at < datetime('now', '-90 days')"
      )
      .run();
    console.log('Database cleanup completed');
  } catch (err) {
    console.error('Database cleanup failed:', err);
  }
}

// ======== 管理者認証ミドルウェア ========
async function adminRequired(c: Context<{ Bindings: Bindings }>, next: () => Promise<void>) {
  const authHeader = c.req.header('Authorization');
  const secret = c.env.ADMIN_SECRET || 'default-secret-key-for-development';

  const isValid = await verifyToken(authHeader, secret);
  if (!isValid) {
    return c.json({ error: '認証が必要です' }, 401);
  }

  await next();
}

// ======== 静的ページ配信 ========

app.get('/', async (c) => {
  if (c.env.ASSETS) {
    const res = await c.env.ASSETS.fetch(new Request(new URL('/index.html', c.req.url)));
    if (res.status < 400) return res;
  }
  return c.text('Not found', 404);
});

app.get('/admin', async (c) => {
  if (c.env.ASSETS) {
    const res = await c.env.ASSETS.fetch(new Request(new URL('/admin.html', c.req.url)));
    if (res.status < 400) return res;
  }
  return c.text('Not found', 404);
});

app.get('/api-document', async (c) => {
  if (c.env.ASSETS) {
    const res = await c.env.ASSETS.fetch(new Request(new URL('/api_document.html', c.req.url)));
    if (res.status < 400) return res;
  }
  return c.text('Not found', 404);
});

app.get('/favicon.ico', (c) => c.body(null, 204));

// ======== 短縮URL作成 API ========

app.post('/shorten', async (c) => {
  try {
    const data = await c.req.json<{
      url?: string;
      access_limit?: number | null;
      expires_at?: string | null;
    }>();

    if (!data || !data.url) {
      return c.json({ error: 'URLが必要です' }, 400);
    }

    const originalUrl = data.url.trim();
    const currentHost = new URL(c.req.url).host;

    // 自身ドメインの短縮防止
    if (originalUrl.includes(currentHost) || originalUrl.includes('s.moyashi.xyz')) {
      await addLog(c.env.DB, 'error', `自身のドメインの短縮は禁止: ${originalUrl}`);
      return c.json({ error: 'このドメインのURLは短縮できません' }, 400);
    }

    if (!isValidUrl(originalUrl)) {
      await addLog(c.env.DB, 'error', `無効なURL形式: ${originalUrl}`);
      return c.json({ error: '無効なURL形式です' }, 400);
    }

    // OGPメタ情報取得
    const meta = await fetchMeta(originalUrl);

    // ユニークな短縮文字列生成
    const shortened = await generateUniqueShortened(c.env.DB);

    const accessLimit =
      data.access_limit !== undefined && data.access_limit !== null
        ? Number(data.access_limit)
        : null;

    let expiresAt = data.expires_at || null;
    if (expiresAt) {
      try {
        const d = new Date(expiresAt);
        if (!isNaN(d.getTime())) {
          expiresAt = d.toISOString().replace('T', ' ').substring(0, 19);
        } else {
          expiresAt = null;
        }
      } catch {
        expiresAt = null;
      }
    }

    // D1 に保存
    await c.env.DB
      .prepare(
        `INSERT INTO url_mapping 
        (shortened, original, og_title, og_description, og_image, created_at, access_limit, expires_at) 
        VALUES (?, ?, ?, ?, ?, datetime('now'), ?, ?)`
      )
      .bind(
        shortened,
        originalUrl,
        meta.title,
        meta.description,
        meta.image,
        accessLimit,
        expiresAt
      )
      .run();

    await addLog(c.env.DB, 'success', `新規URL作成: ${shortened}`, `Original: ${originalUrl}`);

    const baseUrl = getBaseUrl(c);

    return c.json(
      {
        shortened_url: `${baseUrl}/${shortened}`,
        original_url: originalUrl,
        access_limit: accessLimit,
        expires_at: expiresAt,
        og_data: {
          title: meta.title,
          description: meta.description,
          image: meta.image,
        },
        message: 'URLを短縮しました',
      },
      200
    );
  } catch (err: any) {
    console.error('Error in /shorten:', err);
    await addLog(c.env.DB, 'error', `サーバーエラー: ${err?.message || err}`);
    return c.json({ error: 'サーバーエラーが発生しました' }, 500);
  }
});

// ======== 管理者用 API ========

app.post('/admin/auth', async (c) => {
  try {
    const data = await c.req.json<{ secret?: string }>();
    if (!data || !data.secret) {
      return c.json({ error: '認証情報が必要です' }, 400);
    }

    const adminSecret = c.env.ADMIN_SECRET || 'default-secret-key-for-development';
    if (data.secret === adminSecret) {
      const token = await generateToken(adminSecret);
      return c.json({ message: '認証に成功しました', token }, 200);
    }

    const ip = c.req.header('cf-connecting-ip') || 'unknown';
    await addLog(c.env.DB, 'error', `認証失敗: ${ip}`);
    return c.json({ error: '認証に失敗しました' }, 401);
  } catch (err: any) {
    return c.json({ error: '認証エラー' }, 500);
  }
});

app.get('/admin/check-auth', async (c) => {
  const authHeader = c.req.header('Authorization');
  const secret = c.env.ADMIN_SECRET || 'default-secret-key-for-development';
  const isValid = await verifyToken(authHeader, secret);
  if (isValid) {
    return c.json({ authenticated: true }, 200);
  }
  return c.json({ authenticated: false }, 401);
});

app.post('/admin/logout', (c) => {
  return c.json({ message: 'ログアウトしました' }, 200);
});

app.get('/admin/stats', adminRequired, async (c) => {
  const db = c.env.DB;

  const totalUrlsRes = await db.prepare('SELECT COUNT(*) as count FROM url_mapping').first<{ count: number }>();
  const totalAccessesRes = await db
    .prepare('SELECT COALESCE(SUM(access_count), 0) as total FROM url_mapping')
    .first<{ total: number }>();
  const last24hRes = await db
    .prepare("SELECT COUNT(*) as count FROM url_mapping WHERE created_at > datetime('now', '-1 day')")
    .first<{ count: number }>();

  const topUrlsRes = await db
    .prepare(
      'SELECT shortened, original, og_title, access_count FROM url_mapping ORDER BY access_count DESC LIMIT 5'
    )
    .all<{ shortened: string; original: string; og_title: string | null; access_count: number }>();

  return c.json({
    total_urls: totalUrlsRes?.count || 0,
    total_accesses: totalAccessesRes?.total || 0,
    urls_last_24h: last24hRes?.count || 0,
    top_urls: (topUrlsRes.results || []).map((row) => ({
      shortened: row.shortened,
      original: row.original,
      title: row.og_title,
      access_count: row.access_count,
    })),
  });
});

app.get('/admin/system-stats', adminRequired, async (c) => {
  const db = c.env.DB;
  const totalLogs = await db.prepare('SELECT COUNT(*) as count FROM access_logs').first<{ count: number }>();
  const errorLogs = await db
    .prepare("SELECT COUNT(*) as count FROM access_logs WHERE type = 'error'")
    .first<{ count: number }>();
  const recentErrors = await db
    .prepare(
      "SELECT message, timestamp FROM access_logs WHERE type = 'error' ORDER BY timestamp DESC LIMIT 10"
    )
    .all<{ message: string; timestamp: string }>();

  return c.json({
    total_requests: totalLogs?.count || 0,
    error_count: errorLogs?.count || 0,
    blacklisted_ips: 0,
    recent_errors: (recentErrors.results || []).map((e) => `${e.timestamp}: ${e.message}`),
    database_size: 0,
    uptime: 0,
  });
});

app.get('/admin/stats/chart', adminRequired, async (c) => {
  const period = c.req.query('period') || 'daily';
  const db = c.env.DB;

  let query = '';
  if (period === 'daily') {
    query = `
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM url_mapping
      WHERE created_at >= date('now', '-30 days')
      GROUP BY DATE(created_at)
      ORDER BY date
    `;
  } else if (period === 'weekly') {
    query = `
      SELECT strftime('%Y-%W', created_at) as week, COUNT(*) as count
      FROM url_mapping
      WHERE created_at >= date('now', '-84 days')
      GROUP BY week
      ORDER BY week
    `;
  } else {
    query = `
      SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
      FROM url_mapping
      WHERE created_at >= date('now', '-365 days')
      GROUP BY month
      ORDER BY month
    `;
  }

  const { results } = await db.prepare(query).all<{ date?: string; week?: string; month?: string; count: number }>();

  const labels: string[] = [];
  const values: number[] = [];

  for (const row of results || []) {
    labels.push(row.date || row.week || row.month || '');
    values.push(row.count);
  }

  return c.json({ labels, values });
});

app.get('/admin/urls', adminRequired, async (c) => {
  const page = Math.max(1, parseInt(c.req.query('page') || '1'));
  const perPage = Math.max(1, parseInt(c.req.query('per_page') || '10'));
  const sortBy = c.req.query('sort_by') || 'created_at';
  const order = (c.req.query('order') || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const filter = c.req.query('filter') || 'all';
  const searchTerm = (c.req.query('search') || '').trim().toLowerCase();

  const validColumns = ['created_at', 'access_count', 'shortened'];
  const sortColumn = validColumns.includes(sortBy) ? sortBy : 'created_at';

  const whereClauses: string[] = [];
  const params: any[] = [];

  if (filter === 'active') {
    whereClauses.push("(expires_at IS NULL OR expires_at > datetime('now'))");
  } else if (filter === 'expired') {
    whereClauses.push("expires_at <= datetime('now')");
  } else if (filter === 'limited') {
    whereClauses.push('access_limit IS NOT NULL');
  }

  if (searchTerm) {
    whereClauses.push('(LOWER(original) LIKE ? OR LOWER(og_title) LIKE ?)');
    const pattern = `%${searchTerm}%`;
    params.push(pattern, pattern);
  }

  const whereSql = whereClauses.length > 0 ? ` WHERE ${whereClauses.join(' AND ')}` : '';

  const countQuery = `SELECT COUNT(*) as count FROM url_mapping${whereSql}`;
  const totalRes = await c.env.DB.prepare(countQuery).bind(...params).first<{ count: number }>();
  const total = totalRes?.count || 0;

  const offset = (page - 1) * perPage;
  const listQuery = `
    SELECT shortened, original, og_title, og_description, access_count, created_at, access_limit, expires_at
    FROM url_mapping${whereSql}
    ORDER BY ${sortColumn} ${order}
    LIMIT ? OFFSET ?
  `;

  const listParams = [...params, perPage, offset];
  const listRes = await c.env.DB.prepare(listQuery).bind(...listParams).all<UrlMappingRow>();

  return c.json({
    total,
    page,
    per_page: perPage,
    total_pages: Math.ceil(total / perPage),
    urls: (listRes.results || []).map((row) => ({
      shortened: row.shortened,
      original: row.original,
      title: row.og_title,
      description: row.og_description,
      access_count: row.access_count,
      created_at: row.created_at,
      access_limit: row.access_limit,
      expires_at: row.expires_at,
    })),
  });
});

app.get('/admin/url/:shortened/stats', adminRequired, async (c) => {
  const shortened = c.req.param('shortened');
  const row = await c.env.DB.prepare('SELECT access_count FROM url_mapping WHERE shortened = ?')
    .bind(shortened)
    .first<{ access_count: number }>();

  if (!row) {
    return c.json({ error: 'URLが見つかりません' }, 404);
  }

  return c.json({
    labels: ['総アクセス数'],
    values: [row.access_count],
  });
});

app.get('/admin/url/:shortened', adminRequired, async (c) => {
  const shortened = c.req.param('shortened');
  const row = await c.env.DB.prepare(
    'SELECT original, og_title, og_description, og_image, access_count, access_limit, expires_at FROM url_mapping WHERE shortened = ?'
  )
    .bind(shortened)
    .first<UrlMappingRow>();

  if (!row) {
    return c.json({ error: 'URLが見つかりません' }, 404);
  }

  return c.json({
    original_url: row.original,
    og_title: row.og_title,
    og_description: row.og_description,
    og_image: row.og_image,
    access_count: row.access_count,
    access_limit: row.access_limit,
    expires_at: row.expires_at,
  });
});

app.delete('/admin/url/:shortened', adminRequired, async (c) => {
  const shortened = c.req.param('shortened');
  const res = await c.env.DB.prepare('DELETE FROM url_mapping WHERE shortened = ?').bind(shortened).run();

  if (res.meta.changes && res.meta.changes > 0) {
    await addLog(c.env.DB, 'success', `URL削除: ${shortened}`);
    return c.json({ message: 'URLを削除しました' }, 200);
  }

  await addLog(c.env.DB, 'error', `削除失敗: ${shortened} (見つかりません)`);
  return c.json({ error: 'URLが見つかりません' }, 404);
});

app.post('/admin/urls/batch', adminRequired, async (c) => {
  try {
    const data = await c.req.json<{ operation?: string; urls?: string[] }>();
    if (!data || data.operation !== 'delete' || !Array.isArray(data.urls) || data.urls.length === 0) {
      return c.json({ error: '操作とURLの指定が必要です' }, 400);
    }

    const placeholders = data.urls.map(() => '?').join(',');
    const sql = `DELETE FROM url_mapping WHERE shortened IN (${placeholders})`;
    const res = await c.env.DB.prepare(sql).bind(...data.urls).run();
    const deletedCount = res.meta.changes || 0;

    await addLog(c.env.DB, 'success', `一括削除: ${deletedCount}件のURLを削除`);
    return c.json({
      message: `${deletedCount}件のURLを削除しました`,
      deleted_count: deletedCount,
    });
  } catch (err: any) {
    console.error('Batch delete failed:', err);
    return c.json({ error: '操作に失敗しました' }, 500);
  }
});

app.get('/admin/logs', adminRequired, async (c) => {
  const limit = Math.max(1, Math.min(100, parseInt(c.req.query('limit') || '50')));
  const { results } = await c.env.DB
    .prepare('SELECT type, message, details, timestamp FROM access_logs ORDER BY timestamp DESC LIMIT ?')
    .bind(limit)
    .all<AccessLogRow>();

  return c.json(results || []);
});

app.post('/admin/cleanup', adminRequired, async (c) => {
  try {
    await cleanupOldData(c.env.DB);
    return c.json({ message: 'クリーンアップが完了しました' }, 200);
  } catch (err: any) {
    return c.json({ error: 'クリーンアップに失敗しました' }, 500);
  }
});

app.get('/admin/export', adminRequired, async (c) => {
  const format = c.req.query('format') || 'csv';
  if (format !== 'csv') {
    return c.json({ error: '未対応のフォーマットです' }, 400);
  }

  const { results } = await c.env.DB
    .prepare(
      'SELECT shortened, original, og_title, access_count, created_at, access_limit, expires_at FROM url_mapping ORDER BY created_at DESC'
    )
    .all<UrlMappingRow>();

  const baseUrl = getBaseUrl(c);
  let csv = '短縮URL,元URL,タイトル,アクセス数,作成日時,アクセス制限,有効期限\r\n';

  for (const row of results || []) {
    const fullShortUrl = `${baseUrl}/${row.shortened}`;
    const escapeCsv = (str: string | number | null | undefined) => {
      const s = String(str ?? '').replace(/"/g, '""');
      return `"${s}"`;
    };

    csv += [
      escapeCsv(fullShortUrl),
      escapeCsv(row.original),
      escapeCsv(row.og_title || ''),
      row.access_count,
      escapeCsv(row.created_at),
      escapeCsv(row.access_limit !== null ? row.access_limit : '無制限'),
      escapeCsv(row.expires_at || '無期限'),
    ].join(',') + '\r\n';
  }

  return new Response(csv, {
    status: 200,
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename=urls.csv',
    },
  });
});

// ======== リダイレクト エンドポイント ========

app.get('/:shortened', async (c) => {
  const shortened = c.req.param('shortened');

  // 6文字英数チェック (先頭は英字)
  if (!/^[a-zA-Z][a-zA-Z0-9]{5}$/.test(shortened)) {
    await addLog(c.env.DB, 'error', `無効なURL形式: ${shortened}`);
    return c.html(renderError(400, '無効なURL形式です'), 400);
  }

  const row = await c.env.DB
    .prepare(
      'SELECT original, og_title, og_description, og_image, access_count, access_limit, expires_at FROM url_mapping WHERE shortened = ?'
    )
    .bind(shortened)
    .first<UrlMappingRow>();

  if (!row) {
    await addLog(c.env.DB, 'error', `URLが見つかりません: ${shortened}`);
    return c.html(renderError(404, 'URLが見つかりません'), 404);
  }

  // アクセス制限チェック
  if (row.access_limit !== null && row.access_count >= row.access_limit) {
    await addLog(c.env.DB, 'error', `アクセス制限超過: ${shortened}`);
    return c.html(renderExpired('limit_exceeded'), 403);
  }

  // 有効期限チェック
  if (row.expires_at) {
    const expiryTime = new Date(row.expires_at).getTime();
    if (!isNaN(expiryTime) && Date.now() > expiryTime) {
      await addLog(c.env.DB, 'error', `有効期限切れ: ${shortened}`);
      return c.html(renderExpired('expired'), 403);
    }
  }

  // アクセス数加算とログ記録（バックグラウンド実行）
  c.executionCtx.waitUntil(
    Promise.all([
      c.env.DB.prepare('UPDATE url_mapping SET access_count = access_count + 1 WHERE shortened = ?')
        .bind(shortened)
        .run(),
      addLog(c.env.DB, 'success', `リダイレクト: ${shortened}`, `To: ${row.original}`),
    ])
  );

  return c.html(
    renderRedirect(row.original, row.og_title, row.og_description, row.og_image)
  );
});

// 404 ハンドラ
app.notFound((c) => {
  return c.html(renderError(404, 'ページが見つかりません'), 404);
});

// エラーハンドラ
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.html(renderError(500, 'サーバーエラーが発生しました'), 500);
});

// エクスポート: Fetchハンドラ + 定期クリーンアップ用 Cron ハンドラ
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) {
    ctx.waitUntil(cleanupOldData(env.DB));
  },
};
