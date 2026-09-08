const fs = require('fs');
const path = require('path');

const targetFile = path.join(__dirname, '..', 'node_modules', 'workerd', 'lib', 'main.js');

if (fs.existsSync(targetFile)) {
  let content = fs.readFileSync(targetFile, 'utf8');
  if (!content.includes('"win32 arm64 LE"')) {
    content = content.replace(
      '"win32 x64 LE": "@cloudflare/workerd-windows-64"',
      '"win32 x64 LE": "@cloudflare/workerd-windows-64",\n  "win32 arm64 LE": "@cloudflare/workerd-windows-64"'
    );
    fs.writeFileSync(targetFile, content, 'utf8');
    console.log('[patch-workerd] Successfully patched workerd for Windows ARM64');
  }
}
