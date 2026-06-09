import { defineConfig } from 'vite';
import { resolve } from 'path';
import fsp from 'fs/promises';
import fs from 'fs';

// Custom plugin to copy manifest.json, locales, and assets to output directory
const copyExtensionAssets = () => ({
  name: 'copy-extension-assets',
  async closeBundle() {
    const srcDir = resolve(__dirname);
    const destDir = resolve(__dirname, 'dist');

    // Ensure dist exists
    await fsp.mkdir(destDir, { recursive: true });

    // Copy manifest.json
    await fsp.copyFile(
      resolve(srcDir, 'manifest.json'),
      resolve(destDir, 'manifest.json')
    );

    // Helper to recursively copy directories
    const copyDir = async (src, dest) => {
      await fsp.mkdir(dest, { recursive: true });
      const entries = await fsp.readdir(src, { withFileTypes: true });
      for (const entry of entries) {
        const srcPath = resolve(src, entry.name);
        const destPath = resolve(dest, entry.name);
        if (entry.isDirectory()) {
          await copyDir(srcPath, destPath);
        } else {
          await fsp.copyFile(srcPath, destPath);
        }
      }
    };

    // Copy assets and locales if they exist
    const assetsPath = resolve(srcDir, 'assets');
    if (fs.existsSync(assetsPath)) {
      await copyDir(assetsPath, resolve(destDir, 'assets'));
    }

    const localesPath = resolve(srcDir, '_locales');
    if (fs.existsSync(localesPath)) {
      await copyDir(localesPath, resolve(destDir, '_locales'));
    }
  }
});

export default defineConfig({
  plugins: [copyExtensionAssets()],
  build: {
    minify: 'terser',
    sourcemap: false,
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info', 'console.debug']
      },
      mangle: {
        toplevel: true
      }
    },
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/index.html'),
        options: resolve(__dirname, 'src/options/options.html'),
        background: resolve(__dirname, 'src/background/service-worker-entry.js'),
        autofill: resolve(__dirname, 'src/content/autofill.js'),
        'form-detector': resolve(__dirname, 'src/content/form-detector.js'),
        'save-detector': resolve(__dirname, 'src/content/save-detector.js')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (['background', 'autofill', 'form-detector', 'save-detector'].includes(chunkInfo.name)) {
            if (chunkInfo.name === 'background') {
              return 'src/background/service-worker.js';
            }
            return `src/content/${chunkInfo.name}.js`;
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    },
    outDir: 'dist',
    emptyOutDir: true
  }
});
