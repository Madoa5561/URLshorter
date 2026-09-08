import { OgMeta } from './types';

/**
 * 指定したURLから OGP メタデータ（タイトル、説明文、画像）を高速取得する
 * Cloudflare Workers 標準の HTMLRewriter を使用
 */
export async function fetchMeta(url: string): Promise<OgMeta> {
  const result: OgMeta = {
    title: null,
    description: null,
    image: null,
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return result;
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml+xml')) {
      return result;
    }

    let titleTagText = '';
    let inTitleTag = false;

    const rewriter = new HTMLRewriter()
      .on('meta', {
        element(el) {
          const property = el.getAttribute('property')?.toLowerCase();
          const name = el.getAttribute('name')?.toLowerCase();
          const content = el.getAttribute('content');

          if (!content) return;

          // Title
          if (property === 'og:title' || name === 'twitter:title') {
            if (!result.title) result.title = content;
          }
          // Description
          if (
            property === 'og:description' ||
            name === 'twitter:description' ||
            name === 'description'
          ) {
            if (!result.description) result.description = content;
          }
          // Image
          if (property === 'og:image' || name === 'twitter:image') {
            if (!result.image) result.image = content;
          }
        },
      })
      .on('title', {
        element() {
          inTitleTag = true;
        },
        text(textChunk) {
          if (inTitleTag) {
            titleTagText += textChunk.text;
          }
          if (textChunk.lastInTextNode) {
            inTitleTag = false;
          }
        },
      });

    const transformed = rewriter.transform(response);
    const reader = transformed.body?.getReader();
    if (reader) {
      let totalBytes = 0;
      const maxBytes = 128 * 1024; // 128KB 以内でheadタグを走査
      while (totalBytes < maxBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value ? value.length : 0;
        if (result.title && result.description && result.image) {
          reader.cancel();
          break;
        }
      }
    }

    if (!result.title && titleTagText.trim()) {
      result.title = titleTagText.trim();
    }

    return result;
  } catch (err) {
    console.error(`Error fetching metadata for ${url}:`, err);
    return result;
  }
}
