import { escapeHtml } from './utils';

export function renderRedirect(
  originalUrl: string,
  ogTitle?: string | null,
  ogDescription?: string | null,
  ogImage?: string | null
): string {
  const safeTitle = escapeHtml(ogTitle || 'Moyashi URL Shortener');
  const safeDesc = escapeHtml(ogDescription || 'シンプルで使いやすいURL短縮サービス');
  const safeImage = escapeHtml(ogImage || 'https://s.moyashi.xyz/assets/ogp.png');
  const safeOriginalUrl = escapeHtml(originalUrl);

  return `<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>リダイレクト中... - Moyashi URL Shortener</title>
    <meta property="og:title" content="${safeTitle}">
    <meta property="og:description" content="${safeDesc}">
    <meta property="og:image" content="${safeImage}">
    <meta http-equiv="refresh" content="1;url=${safeOriginalUrl}">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@unocss/reset/tailwind.min.css">
    <link rel="stylesheet" href="/theme.css">
    <script src="/theme.js"></script>
    <style>
        body {
            background-color: #18181b;
            color: #f4f4f5;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            margin: 0;
            line-height: 1.6;
        }

        .container {
            max-width: 32rem;
            width: 100%;
            text-align: center;
            background: rgba(39, 39, 42, 0.8);
            backdrop-filter: blur(8px);
            padding: 2rem;
            border-radius: 1rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            border: 1px solid rgba(63, 63, 70, 0.5);
        }

        .logo {
            margin-bottom: 1.5rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        }

        .logo-text {
            font-size: 1.25rem;
            color: #34d399;
        }

        .logo-separator {
            color: #52525b;
            margin: 0 0.5rem;
        }

        .logo-subtext {
            color: #a1a1aa;
            font-size: 0.875rem;
        }

        .spinner {
            width: 2.5rem;
            height: 2.5rem;
            border: 3px solid #27272a;
            border-top-color: #34d399;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 1.5rem auto;
        }

        .message {
            color: #d4d4d8;
            margin-bottom: 1rem;
        }

        .link {
            color: #34d399;
            text-decoration: none;
            transition: color 0.2s ease;
            border-bottom: 1px solid rgba(52, 211, 153, 0.2);
            padding-bottom: 1px;
        }

        .link:hover {
            color: #10b981;
            border-bottom-color: rgba(16, 185, 129, 0.4);
        }

        .background-pattern {
            position: fixed;
            inset: 0;
            background-image: url('https://www.transparenttextures.com/patterns/subtle-dots.png');
            opacity: 0.05;
            pointer-events: none;
            z-index: -1;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        @media (max-width: 640px) {
            .container {
                padding: 1.5rem;
            }
            .logo-text {
                font-size: 1rem;
            }
            .logo-subtext {
                font-size: 0.75rem;
            }
        }
    </style>
</head>
<body>
    <div class="background-pattern"></div>
    <div class="container">
        <div class="logo">
            <span class="logo-text">moyashi</span>
            <span class="logo-separator">//</span>
            <span class="logo-subtext">url.shortener</span>
        </div>
        <div class="spinner"></div>
        <p class="message">リダイレクト中です...</p>
        <p>自動的にリダイレクトされない場合は、<a href="${safeOriginalUrl}" class="link">こちら</a>をクリックしてください。</p>
    </div>
</body>
</html>`;
}
