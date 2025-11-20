from flask import Flask, request, jsonify, render_template, abort, session, make_response
import random
import string
import sqlite3
import requests
from bs4 import BeautifulSoup
from flask_cors import CORS
from urllib.parse import urlparse
import time
from functools import wraps
import re
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
import threading
from datetime import datetime, timedelta, timezone
import io
import csv

# ロギングの設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
logger.addHandler(handler)

# 環境変数の読み込み
load_dotenv()

app = Flask(__name__)
# CORSの設定をより柔軟に
CORS(app, resources={
    r"/*": {
        "origins": "*",  # 開発環境では全てのオリジンを許可
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": True
    }
})
app.config['JSON_AS_ASCII'] = False

# 環境変数からシークレットキーを取る
ADMIN_SECRET = os.getenv('ADMIN_SECRET')
if not ADMIN_SECRET:
    print("警告: ADMIN_SECRETが設定されていません。デフォルトの開発用キーを使用します。")
    ADMIN_SECRET = 'default-secret-key-for-development'

# レート制限の設定
RATE_LIMIT = 75  # クエスト数/分
rate_limit_dict = {}

# グローバル変数
request_stats = {
    'total_requests': 0,
    'error_count': 0,
    'last_errors': [],
    'ip_blacklist': set(),
    'request_times': []
}

# クリーンアップスレッドの管理
cleanup_thread = None

# スレッドセーフなデータベース接続
db_connection = threading.local()

def get_db():
    if not hasattr(db_connection, 'conn'):
        db_connection.conn = sqlite3.connect('urls.db')
        db_connection.conn.row_factory = sqlite3.Row
    return db_connection.conn

def close_db():
    if hasattr(db_connection, 'conn'):
        db_connection.conn.close()
        del db_connection.conn

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not session.get('admin_authenticated'):
            return jsonify({"error": "認証が必要です"}), 401
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        current_time = time.time()
        
        # 古いエントリを削除
        if ip in rate_limit_dict:
            rate_limit_dict[ip] = [t for t in rate_limit_dict[ip] if current_time - t < 60]
        
        # 新しいリクエストを追加
        if ip not in rate_limit_dict:
            rate_limit_dict[ip] = []
        rate_limit_dict[ip].append(current_time)
        
        # レート制限をチェク
        if len(rate_limit_dict[ip]) > RATE_LIMIT:
            return jsonify({
                "error": "レート制限を超えました。しばらく待ってから再試行してください。",
                "retry_after": "60秒"
            }), 429
        
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # url_mappingテーブルの作成
    c.execute('''
        CREATE TABLE IF NOT EXISTS url_mapping (
            shortened TEXT PRIMARY KEY,
            original TEXT NOT NULL,
            og_title TEXT,
            og_description TEXT,
            og_image TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            access_count INTEGER DEFAULT 0,
            access_limit INTEGER DEFAULT NULL,
            expires_at TIMESTAMP DEFAULT NULL
        )
    ''')
    
    # 既存のテーブルにカラムが存在しない場合は追加
    try:
        c.execute('SELECT access_limit FROM url_mapping LIMIT 1')
    except sqlite3.OperationalError:
        c.execute('ALTER TABLE url_mapping ADD COLUMN access_limit INTEGER DEFAULT NULL')
        
    try:
        c.execute('SELECT expires_at FROM url_mapping LIMIT 1')
    except sqlite3.OperationalError:
        c.execute('ALTER TABLE url_mapping ADD COLUMN expires_at TIMESTAMP DEFAULT NULL')
    
    # ログテーブルの作成
    c.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    close_db()

def add_log(type, message, details=None):
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT INTO access_logs (type, message, details)
        VALUES (?, ?, ?)
    ''', (type, message, details))
    conn.commit()
    close_db()

def get_logs(limit=50):
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT type, message, details, timestamp
        FROM access_logs
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    logs = [{
        'type': row[0],
        'message': row[1],
        'details': row[2],
        'timestamp': row[3]
    } for row in c.fetchall()]
    close_db()
    return logs

def is_valid_url(url):
    try:
        # URLの基本的な形式を確認
        if not isinstance(url, str):
            return False
            
        # URLの長さチェック（最小長を3に緩和）
        if len(url) > 2000 or len(url) < 3:
            return False
            
        result = urlparse(url)
        
        # 基本的なURLの構造チェック
        if not all([
            result.scheme,  # スキームが存在すること
            result.netloc,  # ドメインが存在すること
        ]):
            return False
        
        # 危険性の高いスキームのみをブロック
        dangerous_schemes = ['javascript', 'data', 'file']
        if result.scheme.lower() in dangerous_schemes:
            return False
        
        # 最小限の危険文字チェック
        dangerous_chars = ['<', '>', '{', '}', '|']
        if any(char in url for char in dangerous_chars):
            return False
            
        # URLが実際にアクセス可能かの簡易チェック
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                return True
        except requests.exceptions.RequestException:
            pass
            
        # HEADリクエストが失敗してもURLとして有効と判断
        return True
            
    except Exception as e:
        logger.error(f"Error validating URL: {e}")
        return False

def fetch_meta(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
        }
        response = requests.get(url, headers=headers, timeout=5, verify=True)
        response.encoding = response.apparent_encoding
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # より柔軟なメタデータ取得
        og_title = (
            soup.find('meta', property='og:title') or 
            soup.find('meta', property='twitter:title') or 
            soup.find('title')
        )
        
        og_description = (
            soup.find('meta', property='og:description') or 
            soup.find('meta', property='twitter:description') or 
            soup.find('meta', attrs={'name': 'description'})
        )
        
        og_image = (
            soup.find('meta', property='og:image') or 
            soup.find('meta', property='twitter:image')
        )
        
        return {
            'title': og_title.get('content', og_title.string) if og_title else None,
            'description': og_description.get('content', og_description.string) if og_description else None,
            'image': og_image['content'] if og_image else None
        }
    except Exception as e:
        print(f"Error fetching metadata: {e}")
        return {
            'title': None,
            'description': None,
            'image': None
        }

def generate_random_string(length=6):
    # 紛らわしい文字を除外し、より読みやすい文字セットを使用
    safe_chars = ''.join(c for c in string.ascii_letters + string.digits 
                        if c not in 'Il1O0o')
    # 最初の文字は数字以外（より読みやすく
    first = ''.join(c for c in safe_chars if not c.isdigit())
    rest = safe_chars
    
    # 禁止パターンをチェックする関数
    def is_safe_string(s):
        # 不適切な単語のリスト
        forbidden_words = ['xxx', 'sex', 'fuck', 'shit', 'dick', 'porn']
        return not any(word in s.lower() for word in forbidden_words)
    
    # 安全な文字列が生成されるまで繰り返す
    while True:
        result = random.choice(first) + ''.join(random.choice(rest) for _ in range(length - 1))
        if is_safe_string(result):
            return result

def get_shortened_url(original_url):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT shortened FROM url_mapping WHERE original = ?', (original_url,))
    result = c.fetchone()
    close_db()
    return result[0] if result else None

def generate_unique_shortened():
    while True:
        shortened = generate_random_string()
        if not get_url_info(shortened):
            return shortened

def parse_datetime(datetime_str):
    """日時文字列をパースしてUTC datetimeオブジェクトを返す"""
    if not datetime_str:
        return None
    try:
        # ISO 8601形式の場合
        if 'T' in datetime_str:
            # ミリ秒とタイムゾーン部分を処理
            dt_str = datetime_str.split('.')[0]
            if 'Z' in datetime_str:
                dt = datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S')
                return dt.replace(tzinfo=timezone.utc)
            else:
                dt = datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S')
                return dt.astimezone(timezone.utc)
        else:
            # 従来の形式の場合（ローカルタイムとして解釈してUTCに変換）
            dt = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
            local_tz = datetime.now(timezone.utc).astimezone().tzinfo
            return dt.replace(tzinfo=local_tz).astimezone(timezone.utc)
    except ValueError as e:
        logger.error(f'日時解析エラー: {e}')
        return None

def format_datetime_for_db(dt):
    """datetimeオブジェクトをデータベース保存用の文字列に変換"""
    if not dt:
        return None
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def save_url_mapping_with_meta(shortened, original, meta, access_limit=None, expires_at=None):
    conn = get_db()
    c = conn.cursor()
    try:
        # expires_atをパースしてUTC形式で保存
        parsed_expires_at = None
        if expires_at:
            parsed_expires_at = format_datetime_for_db(parse_datetime(expires_at))
        
        c.execute('''
            INSERT INTO url_mapping 
            (shortened, original, og_title, og_description, og_image, created_at, access_limit, expires_at) 
            VALUES (?, ?, ?, ?, ?, datetime('now'), ?, ?)
        ''', (
            shortened,
            original,
            meta.get('title'),
            meta.get('description'),
            meta.get('image'),
            access_limit,
            parsed_expires_at
        ))
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        conn.rollback()
        raise
    finally:
        close_db()

def increment_access_count(shortened):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE url_mapping SET access_count = access_count + 1 WHERE shortened = ?', (shortened,))
    conn.commit()
    close_db()

def get_url_info(shortened):
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT original, og_title, og_description, og_image, access_count, access_limit, expires_at 
        FROM url_mapping 
        WHERE shortened = ?
    ''', (shortened,))
    result = c.fetchone()
    close_db()
    
    if result:
        return {
            'original_url': result[0],
            'og_title': result[1],
            'og_description': result[2],
            'og_image': result[3],
            'access_count': result[4],
            'access_limit': result[5],
            'expires_at': result[6]
        }
    return None

def get_stats():
    conn = get_db()
    c = conn.cursor()
    
    # 総URL数
    c.execute('SELECT COUNT(*) FROM url_mapping')
    total_urls = c.fetchone()[0]
    
    # 総アクセス数
    c.execute('SELECT SUM(access_count) FROM url_mapping')
    total_accesses = c.fetchone()[0] or 0
    
    # 過去24時間の新規URL数
    c.execute('''
        SELECT COUNT(*) FROM url_mapping 
        WHERE created_at > datetime('now', '-1 day')
    ''')
    urls_last_24h = c.fetchone()[0]
    
    # 最もアクセスの多いURL Top 5
    c.execute('''
        SELECT shortened, original, og_title, access_count 
        FROM url_mapping 
        ORDER BY access_count DESC 
        LIMIT 5
    ''')
    top_urls = [{
        'shortened': row[0],
        'original': row[1],
        'title': row[2],
        'access_count': row[3]
    } for row in c.fetchall()]
    
    close_db()
    
    return {
        'total_urls': total_urls,
        'total_accesses': total_accesses,
        'urls_last_24h': urls_last_24h,
        'top_urls': top_urls
    }

def get_url_list(page=1, per_page=10, sort_by='created_at', order='desc'):
    conn = get_db()
    c = conn.cursor()
    
    # 総URL数を取得
    c.execute('SELECT COUNT(*) FROM url_mapping')
    total = c.fetchone()[0]
    
    # ページネーション用のオフセットを計算
    offset = (page - 1) * per_page
    
    # URLリストを取得
    valid_columns = ['created_at', 'access_count', 'shortened']
    sort_column = sort_by if sort_by in valid_columns else 'created_at'
    sort_order = 'DESC' if order.lower() == 'desc' else 'ASC'
    
    c.execute(f'''
        SELECT shortened, original, og_title, og_description, access_count, created_at
        FROM url_mapping
        ORDER BY {sort_column} {sort_order}
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    
    urls = [{
        'shortened': row[0],
        'original': row[1],
        'title': row[2],
        'description': row[3],
        'access_count': row[4],
        'created_at': row[5]
    } for row in c.fetchall()]
    
    close_db()
    
    return {
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page,
        'urls': urls
    }

# エラーハンドリング
@app.errorhandler(404)
def not_found_error(error):
    add_log('error', f'404エラー: {request.url}')
    return render_template('error.html', 
        error="ページが見つかりません",
        code=404
    ), 404

@app.errorhandler(500)
def internal_error(error):
    add_log('error', f'500エラー: {str(error)}')
    db = get_db()
    db.rollback()
    close_db()
    return render_template('error.html',
        error="サーバーエラーが発生しました",
        code=500
    ), 500

# セキュリティミドルウェア
def security_middleware():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # リクエスト数の制限
            request_stats['total_requests'] += 1
            
            # IPブラックリストのチェック
            if request.remote_addr in request_stats['ip_blacklist']:
                add_log('error', f'ブラックリストIPからのアクセス: {request.remote_addr}')
                abort(403)
            
            # 異常なリクエストパターンの検出
            current_time = time.time()
            request_stats['request_times'] = [t for t in request_stats['request_times'] 
                                            if current_time - t < 60]
            request_stats['request_times'].append(current_time)
            
            if len(request_stats['request_times']) > 100:  # 1分間に100リクエスト以上
                request_stats['ip_blacklist'].add(request.remote_addr)
                add_log('error', f'レート制限超過によるブラックリスト追加: {request.remote_addr}')
                abort(429)
            
            # ベーシックなセキュリティヘッダーの追加
            response = f(*args, **kwargs)
            if isinstance(response, tuple):
                response, status_code = response
            else:
                status_code = 200
                
            if isinstance(response, (dict, list)):
                response = jsonify(response)
                
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            return response, status_code
            
        return wrapped
    return decorator

# パフォーマンスモニタリング
def monitor_performance():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            start_time = time.time()
            result = f(*args, **kwargs)
            end_time = time.time()
            
            # 実行時間の記録
            execution_time = end_time - start_time
            logger.info(f'Performance: {f.__name__} took {execution_time:.2f} seconds')
            
            # 遅いリクエストの検出
            if execution_time > 1.0:  # 1秒以上かかるリクエスト
                logger.warning(f'遅いリクエスト検出: {f.__name__} took {execution_time:.2f} seconds')
            
            return result
        return wrapped
    return decorator

# データベースクリーンアップ
def cleanup_old_data():
    try:
        conn = get_db()
        c = conn.cursor()
        
        # 古いログの削除（30日以上前）
        c.execute('''
            DELETE FROM access_logs 
            WHERE timestamp < datetime('now', '-30 days')
        ''')
        
        # 未使用のURLの削除（90日以上アクセスがない）
        c.execute('''
            DELETE FROM url_mapping 
            WHERE access_count = 0 
            AND created_at < datetime('now', '-90 days')
        ''')
        
        conn.commit()
        logger.info('Database cleanup completed successfully')
    except Exception as e:
        logger.error(f'Database cleanup failed: {e}')
        conn.rollback()
    finally:
        close_db()

# 定期的なクリーンアップの実行
def schedule_cleanup():
    global cleanup_thread
    cleanup_old_data()
    # 24時間ごとに実行
    cleanup_thread = threading.Timer(86400, schedule_cleanup)
    cleanup_thread.daemon = True  # デーモンスレッドとして実行
    cleanup_thread.start()

# アプリケーション初期化時の処理
def init_app():
    init_db()
    schedule_cleanup()
    logger.info('Application initialized successfully')

# アプリケーション終了時の処理
def cleanup_app():
    global cleanup_thread
    if cleanup_thread:
        cleanup_thread.cancel()
        cleanup_thread = None
    logger.info('Application cleanup completed')

# URLエンドポイントの強化
@app.route('/shorten', methods=['POST'])
@rate_limit
@security_middleware()
@monitor_performance()
def shorten_url():
    """URLを短縮するエンドポイント"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URLが必要です"}), 400

        original_url = data['url'].strip()
        
        # 自身のドメインへの短縮を防止
        if 's.moyashi.xyz' in original_url:
            add_log('error', f'自身のドメインの短縮は禁止: {original_url}')
            return jsonify({"error": "このドメインのURLは短縮できません"}), 400
        
        # URL検証
        if not is_valid_url(original_url):
            add_log('error', f'無効なURL形式: {original_url}')
            return jsonify({"error": "無効なURL形式です"}), 400

        # メタデータ取得とURL保存
        meta = fetch_meta(original_url)
        shortened = generate_unique_shortened()
        
        try:
            # アクセス制限と有効期限の取得
            access_limit = data.get('access_limit')
            expires_at = data.get('expires_at')
            
            save_url_mapping_with_meta(shortened, original_url, meta, access_limit, expires_at)
        except Exception as e:
            logger.error(f'URL保存エラー: {str(e)}')
            return jsonify({"error": "URLの保存に失敗しました"}), 500
        
        add_log('success', f'新規URL作成: {shortened}', f'Original: {original_url}')
        
        return jsonify({
            "shortened_url": f"https://s.moyashi.xyz/{shortened}",
            "original_url": original_url,
            "access_limit": access_limit,
            "expires_at": expires_at,
            "og_data": {
                "title": meta.get('title'),
                "description": meta.get('description'),
                "image": meta.get('image')
            },
            "message": "URLを短縮しました"
        }), 200
        
    except Exception as e:
        logger.error(f'Error in shorten_url: {e}', exc_info=True)
        add_log('error', f'サーバーエラー: {str(e)}')
        return jsonify({"error": "サーバーエラーが発生しました"}), 500

# faviconのルート（エラーログを出さないように最初に定義）
@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/<shortened>')
def redirect_to_original(shortened):
    # 短コードの検証（より厳密に）
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9]{5}$', shortened):
        add_log('error', f'無効なURL形式: {shortened}')
        return render_template('error.html', 
            error="無効なURL形式です",
            original_url="#"
        ), 400
    
    url_info = get_url_info(shortened)
    
    if not url_info:
        add_log('error', f'URLが見つかりません: {shortened}')
        return render_template('error.html', 
            error="URLが見つかりません",
            original_url="#"
        ), 404
    
    # アクセス制限のチェック
    if url_info['access_limit'] is not None and url_info['access_count'] >= url_info['access_limit']:
        add_log('error', f'アクセス制限超過: {shortened}')
        return render_template('expired.html',
            error_type='limit_exceeded'
        ), 403
    
    # 有効期限のチェック
    if is_expired(url_info['expires_at']):
        add_log('error', f'有効期限切れ: {shortened}')
        return render_template('expired.html',
            error_type='expired'
        ), 403
    
    # URLの有効性を再確認
    if not is_valid_url(url_info['original_url']):
        add_log('error', f'無効なURL: {url_info["original_url"]}')
        return render_template('error.html',
            error="無効なURLです",
            original_url="#"
        ), 400
    
    # アクセスカウントを増やす
    try:
        increment_access_count(shortened)
        add_log('success', f'リダイレクト: {shortened}', f'To: {url_info["original_url"]}')
    except Exception as e:
        print(f"Error incrementing access count: {e}")
    
    return render_template('redirect.html',
        original_url=url_info['original_url'],
        og_title=url_info['og_title'],
        og_description=url_info['og_description'],
        og_image=url_info['og_image']
    )

# 管理用APIの強化
@app.route('/admin/system-stats')
@admin_required
@monitor_performance()
def system_stats():
    """システム統計情報を取得するエンドポイント"""
    stats = {
        'total_requests': request_stats['total_requests'],
        'error_count': request_stats['error_count'],
        'blacklisted_ips': len(request_stats['ip_blacklist']),
        'recent_errors': request_stats['last_errors'][-10:],  # 最新10件のエラー
        'database_size': os.path.getsize('urls.db') / (1024 * 1024),  # MBサイズ
        'uptime': time.time() - app.start_time
    }
    return jsonify(stats)

@app.route('/admin/cleanup', methods=['POST'])
@admin_required
def manual_cleanup():
    """手動でデータベースクリーンアップを実行するエンドポイント"""
    try:
        cleanup_old_data()
        return jsonify({"message": "クリーンアップが完了しました"}), 200
    except Exception as e:
        logger.error(f'Manual cleanup failed: {e}')
        return jsonify({"error": "クリーンアップに失敗しました"}), 500

# 管理用APIエンドポイント
@app.route('/admin/stats')
@admin_required
def admin_stats():
    """統計情報を取得するエンドポイント"""
    return jsonify(get_stats())

@app.route('/admin/urls')
@admin_required
def admin_urls():
    """URLリストを取得するエンドポイント"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    sort_by = request.args.get('sort_by', 'created_at')
    order = request.args.get('order', 'desc')
    filter_type = request.args.get('filter', 'all')
    search_term = request.args.get('search', '').strip().lower()

    conn = get_db()
    c = conn.cursor()

    # 基本のSQLクエリ
    base_query = '''
        SELECT shortened, original, og_title, og_description, access_count, created_at, access_limit, expires_at
        FROM url_mapping
    '''
    count_query = 'SELECT COUNT(*) FROM url_mapping'
    where_clauses = []
    params = []

    # フィルター条件の追加
    if filter_type == 'active':
        where_clauses.append('(expires_at IS NULL OR expires_at > datetime("now"))')
    elif filter_type == 'expired':
        where_clauses.append('expires_at <= datetime("now")')
    elif filter_type == 'limited':
        where_clauses.append('access_limit IS NOT NULL')

    # 検索条件の追加
    if search_term:
        where_clauses.append('(LOWER(original) LIKE ? OR LOWER(og_title) LIKE ?)')
        search_pattern = f'%{search_term}%'
        params.extend([search_pattern, search_pattern])

    # WHERE句の構築
    if where_clauses:
        where_clause = ' WHERE ' + ' AND '.join(where_clauses)
        base_query += where_clause
        count_query += where_clause

    # 総件数の取得
    c.execute(count_query, params)
    total = c.fetchone()[0]

    # ソート順の設定
    valid_columns = ['created_at', 'access_count', 'shortened']
    sort_column = sort_by if sort_by in valid_columns else 'created_at'
    sort_order = 'DESC' if order.lower() == 'desc' else 'ASC'
    base_query += f' ORDER BY {sort_column} {sort_order}'

    # ページネーション
    offset = (page - 1) * per_page
    base_query += ' LIMIT ? OFFSET ?'
    params.extend([per_page, offset])

    # URLリストの取得
    c.execute(base_query, params)
    urls = [{
        'shortened': row[0],
        'original': row[1],
        'title': row[2],
        'description': row[3],
        'access_count': row[4],
        'created_at': row[5],
        'access_limit': row[6],
        'expires_at': row[7]
    } for row in c.fetchall()]

    close_db()

    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page,
        'urls': urls
    })

@app.route('/admin/url/<shortened>', methods=['DELETE'])
@admin_required
def admin_delete_url(shortened):
    """URLを削除するエンドポイント"""
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM url_mapping WHERE shortened = ?', (shortened,))
    deleted = c.rowcount > 0
    conn.commit()
    close_db()
    
    if deleted:
        add_log('success', f'URL削除: {shortened}')
        return jsonify({"message": "URLを削除しました"}), 200
    
    add_log('error', f'削除失敗: {shortened} (見つかりません)')
    return jsonify({"error": "URLが見つかりません"}), 404

@app.route('/admin/url/<shortened>')
@admin_required
def admin_url_details(shortened):
    """URL詳細を取得するエンドポイント"""
    url_info = get_url_info(shortened)
    if url_info:
        return jsonify(url_info), 200
    return jsonify({"error": "URLが見つかりません"}), 404

@app.route('/admin/logs')
@admin_required
def admin_logs():
    """ログを取得するエンドポイント"""
    return jsonify(get_logs())

@app.route('/admin')
def admin_page():
    """管理画面を表示するエンドポイント"""
    return render_template('admin.html')

@app.route('/')
def index():
    """トップページを表示するエンドポイント"""
    return render_template('index.html')

@app.route('/api-document')
def api_document():
    """Api Document ページを表示する"""
    return render_template('api_document.html')

# セッション設定
app.secret_key = ADMIN_SECRET  # セッション用のシークレットキー

# 認証関連のエンドポイント
@app.route('/admin/auth', methods=['POST'])
def admin_auth():
    """管理者認証エンドポイント"""
    data = request.get_json()
    if not data or 'secret' not in data:
        return jsonify({"error": "認証情報が必要です"}), 400
        
    if data['secret'] == ADMIN_SECRET:
        session['admin_authenticated'] = True
        session.permanent = True  # セッションの永続化
        app.permanent_session_lifetime = timedelta(days=1)  # セッション有期限を1日に設定
        
        # セキュリティトークンを生成
        token = os.urandom(32).hex()
        session['admin_token'] = token
        
        return jsonify({
            "message": "認証に成功しました",
            "token": token
        }), 200
    
    # 失敗した認証試行をログに記録
    add_log('error', f'認証失敗: {request.remote_addr}')
    return jsonify({"error": "認証に失敗しました"}), 401

@app.route('/admin/check-auth')
def admin_check_auth():
    """認証状態確認エンドポイント"""
    auth_header = request.headers.get('Authorization')
    if session.get('admin_authenticated') and auth_header == session.get('admin_token'):
        return jsonify({"authenticated": True}), 200
    return jsonify({"authenticated": False}), 401

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    """ログアウトエンドポイント"""
    if session.get('admin_authenticated'):
        add_log('info', f'管理者ログアウト: {request.remote_addr}')
    session.clear()
    return jsonify({"message": "ログアウトしました"}), 200

@app.route('/admin/stats/chart')
@admin_required
def admin_stats_chart():
    """アクセス統計チャートデータを取得するエンドポイント"""
    period = request.args.get('period', 'daily')
    conn = get_db()
    c = conn.cursor()
    
    if period == 'daily':
        # 日別のアクセス統計（過去30日）
        c.execute('''
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM url_mapping
            WHERE created_at >= date('now', '-30 days')
            GROUP BY DATE(created_at)
            ORDER BY date
        ''')
    elif period == 'weekly':
        # 週別のアクセス統計（過去12週）
        c.execute('''
            SELECT strftime('%Y-%W', created_at) as week, COUNT(*) as count
            FROM url_mapping
            WHERE created_at >= date('now', '-84 days')
            GROUP BY week
            ORDER BY week
        ''')
    else:  # monthly
        # 月別のアクセス統計（過去12ヶ月）
        c.execute('''
            SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
            FROM url_mapping
            WHERE created_at >= date('now', '-365 days')
            GROUP BY month
            ORDER BY month
        ''')
    
    stats = c.fetchall()
    close_db()
    
    # データを整形
    labels = []
    values = []
    for stat in stats:
        labels.append(stat[0])
        values.append(stat[1])
    
    return jsonify({
        'labels': labels,
        'values': values
    })

@app.route('/admin/export')
@admin_required
def export_data():
    """URLデータをエクスポートするエンドポイント"""
    format = request.args.get('format', 'csv')
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''
        SELECT shortened, original, og_title, access_count, created_at, access_limit, expires_at
        FROM url_mapping
        ORDER BY created_at DESC
    ''')
    
    data = c.fetchall()
    close_db()
    
    if format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['短縮URL', '元URL', 'イトル', 'アクセス数', '作成日時', 'アクセス制限', '有効期限'])
        
        for row in data:
            writer.writerow([
                f'https://s.moyashi.xyz/{row[0]}',
                row[1],
                row[2] or '',
                row[3],
                row[4],
                row[5] or '無制限',
                row[6] or '無期限'
            ])
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=urls.csv'
        return response
    
    return jsonify({"error": "未対応のフォーマットです"}), 400

@app.route('/admin/urls/batch', methods=['POST'])
@admin_required
def batch_operation():
    """URLの一括操作を行うエンドポイント"""
    data = request.get_json()
    if not data or 'operation' not in data or 'urls' not in data:
        return jsonify({"error": "操作とURLの指定が必要です"}), 400
    
    operation = data['operation']
    urls = data['urls']
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        if operation == 'delete':
            # 一括削除
            placeholders = ','.join(['?' for _ in urls])
            c.execute(f'DELETE FROM url_mapping WHERE shortened IN ({placeholders})', urls)
            deleted_count = c.rowcount
            conn.commit()
            add_log('success', f'一括削除: {deleted_count}件のURLを削除')
            return jsonify({
                "message": f"{deleted_count}件のURLを削除しました",
                "deleted_count": deleted_count
            })
        else:
            return jsonify({"error": "未対応の操作です"}), 400
    except Exception as e:
        conn.rollback()
        logger.error(f'Batch operation failed: {e}')
        return jsonify({"error": "操作に失敗しました"}), 500
    finally:
        close_db()

def is_expired(expires_at):
    """URLが期限切れかどうかを判定"""
    if not expires_at:
        return False
    
    try:
        # 文字列をdatetimeオブジェクトに変換
        if isinstance(expires_at, str):
            expiry_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        else:
            expiry_date = expires_at
            
        # タイムゾーンが設定されていない場合はUTCとして扱う
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            
        now = datetime.now(timezone.utc)
        return now > expiry_date
    except Exception as e:
        logger.error(f'期限切れチェックエラー: {e}')
        return False

if __name__ == '__main__':
    app.start_time = time.time()
    init_app()
    try:
        app.run(debug=True, port=5000)
    finally:
        cleanup_app() 