const BASE_URL = 'http://127.0.0.1:8787';

async function runTests() {
  console.log('--- Starting URLshorter-CF verification tests ---');
  let testsPassed = 0;
  let testsFailed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`✅ PASS: ${message}`);
      testsPassed++;
    } else {
      console.error(`❌ FAIL: ${message}`);
      testsFailed++;
    }
  }

  try {
    // Test 1: GET / (Top page)
    const indexRes = await fetch(`${BASE_URL}/`);
    assert(indexRes.status === 200, `GET / status is 200 (got ${indexRes.status})`);
    const indexHtml = await indexRes.text();
    assert(indexHtml.includes('URL') || indexHtml.includes('html'), 'GET / returns HTML content');

    // Test 2: GET /api-document
    const apiDocRes = await fetch(`${BASE_URL}/api-document`);
    assert(apiDocRes.status === 200, `GET /api-document status is 200 (got ${apiDocRes.status})`);

    // Test 3: GET /admin
    const adminRes = await fetch(`${BASE_URL}/admin`);
    assert(adminRes.status === 200, `GET /admin status is 200 (got ${adminRes.status})`);

    // Test 4: POST /shorten
    const shortenRes = await fetch(`${BASE_URL}/shorten`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: 'https://example.com',
      }),
    });
    assert(shortenRes.status === 200, `POST /shorten status is 200 (got ${shortenRes.status})`);
    const shortenData = await shortenRes.json();
    console.log('Shorten response:', shortenData);
    assert(shortenData.shortened_url, `shortened_url returned: ${shortenData.shortened_url}`);
    assert(shortenData.original_url === 'https://example.com', 'original_url matches');

    const shortenedCode = shortenData.shortened_url.split('/').pop();
    console.log(`Generated code: ${shortenedCode}`);

    // Test 5: GET /:shortened (Redirect page)
    const redirectRes = await fetch(`${BASE_URL}/${shortenedCode}`);
    assert(redirectRes.status === 200, `GET /${shortenedCode} status is 200 (got ${redirectRes.status})`);
    const redirectHtml = await redirectRes.text();
    assert(redirectHtml.includes('https://example.com'), 'Redirect HTML contains original URL');

    // Test 6: Auth tests
    const badAuthRes = await fetch(`${BASE_URL}/admin/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: 'wrong-secret' }),
    });
    assert(badAuthRes.status === 401, 'POST /admin/auth with bad secret is 401');

    const goodAuthRes = await fetch(`${BASE_URL}/admin/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: 'admin12345' }),
    });
    assert(goodAuthRes.status === 200, 'POST /admin/auth with correct secret is 200');
    const authData = await goodAuthRes.json();
    const token = authData.token;
    assert(token && token.includes('.'), `Token returned: ${token?.substring(0, 15)}...`);

    // Test 7: GET /admin/check-auth
    const checkAuthRes = await fetch(`${BASE_URL}/admin/check-auth`, {
      headers: { Authorization: token },
    });
    assert(checkAuthRes.status === 200, 'GET /admin/check-auth is 200');

    // Test 8: GET /admin/stats
    const statsRes = await fetch(`${BASE_URL}/admin/stats`, {
      headers: { Authorization: token },
    });
    assert(statsRes.status === 200, 'GET /admin/stats is 200');
    const statsData = await statsRes.json();
    console.log('Stats response:', statsData);
    assert(statsData.total_urls >= 1, `total_urls >= 1 (got ${statsData.total_urls})`);
    assert(statsData.total_accesses >= 1, `total_accesses >= 1 (got ${statsData.total_accesses})`);

    // Test 9: GET /admin/urls
    const urlsRes = await fetch(`${BASE_URL}/admin/urls`, {
      headers: { Authorization: token },
    });
    assert(urlsRes.status === 200, 'GET /admin/urls is 200');
    const urlsData = await urlsRes.json();
    assert(urlsData.urls && urlsData.urls.length >= 1, `URLs list count: ${urlsData.urls?.length}`);

    // Test 10: GET /admin/url/:shortened/stats
    const urlStatsRes = await fetch(`${BASE_URL}/admin/url/${shortenedCode}/stats`, {
      headers: { Authorization: token },
    });
    assert(urlStatsRes.status === 200, `GET /admin/url/${shortenedCode}/stats is 200`);

    // Test 11: GET /admin/export
    const exportRes = await fetch(`${BASE_URL}/admin/export?format=csv`, {
      headers: { Authorization: token },
    });
    assert(exportRes.status === 200, 'GET /admin/export is 200');
    const csvText = await exportRes.text();
    assert(csvText.includes('短縮URL'), 'Export CSV header is present');

    // Test 12: Limited access URL (limit = 1)
    const limitedShorten = await fetch(`${BASE_URL}/shorten`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: 'https://cloudflare.com',
        access_limit: 1,
      }),
    });
    const limitedData = await limitedShorten.json();
    const limitedCode = limitedData.shortened_url.split('/').pop();

    // 1st access should succeed (access count becomes 1)
    const firstAccess = await fetch(`${BASE_URL}/${limitedCode}`);
    assert(firstAccess.status === 200, '1st access to limited URL succeeds');

    // Wait a brief moment for async increment
    await new Promise((r) => setTimeout(r, 200));

    // 2nd access should be 403 limit exceeded
    const secondAccess = await fetch(`${BASE_URL}/${limitedCode}`);
    assert(secondAccess.status === 403, `2nd access to limited URL returns 403 (got ${secondAccess.status})`);
    const expiredHtml = await secondAccess.text();
    assert(expiredHtml.includes('URLが期限切れです') || expiredHtml.includes('最大アクセス回数'), 'Expired HTML is rendered');

    // Test 13: DELETE /admin/url/:shortened
    const deleteRes = await fetch(`${BASE_URL}/admin/url/${limitedCode}`, {
      method: 'DELETE',
      headers: { Authorization: token },
    });
    assert(deleteRes.status === 200, 'DELETE /admin/url/:shortened returns 200');

  } catch (err) {
    console.error('Test execution error:', err);
    testsFailed++;
  }

  console.log(`\n========================================`);
  console.log(`Total tests passed: ${testsPassed}`);
  console.log(`Total tests failed: ${testsFailed}`);
  console.log(`========================================`);

  if (testsFailed > 0) {
    process.exit(1);
  }
}

runTests();
