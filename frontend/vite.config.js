import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import fs from 'fs'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // Serve i file JSON da results/alerts quando si richiede /data/alerts/*
    {
      name: 'serve-alerts-from-results',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const match = req.url?.match(/^\/data\/alerts\/([^?]+)/);
          if (!match) return next();
          const filename = decodeURIComponent(match[1]);
          const filePath = path.resolve(process.cwd(), '..', 'results', 'alerts', filename);
          if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
            return next();
          }
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Cache-Control', 'no-cache');
          fs.createReadStream(filePath).pipe(res);
        });
      }
    }
  ],
  server: {
    fs: {
      // Permetti di servire file dalla cartella superiore (dove c'è results)
      allow: ['..']
    }
  }
})