const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, '..', 'clients', 'desktop-tauri', 'src');
const destDir = path.join(__dirname, '..', 'dist-pages');

function copyFolderRecursive(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyFolderRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

try {
  console.log('Cleaning up existing dist-pages folder...');
  if (fs.existsSync(destDir)) {
    fs.rmSync(destDir, { recursive: true, force: true });
  }
  console.log(`Copying static assets from ${srcDir} to ${destDir}...`);
  copyFolderRecursive(srcDir, destDir);
  console.log('Static pages prepared successfully in "dist-pages" folder!');
} catch (err) {
  console.error('Error packaging static pages:', err);
  process.exit(1);
}
