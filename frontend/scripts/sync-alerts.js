import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..', '..');
const sourceDir = path.join(projectRoot, 'results', 'alerts');
const outPath = path.join(projectRoot, 'frontend', 'src', 'data', 'reportsData.js');

const formatLabel = (filename) => {
  return filename
    .replace(/_alerts\.json$/, '')
    .replace(/\.json$/, '')
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ') + ' Alerts';
};

const availableReports = [];
const reportsData = {};
let allAlerts = [];

if (fs.existsSync(sourceDir)) {
  const files = fs.readdirSync(sourceDir).filter((f) => f.endsWith('.json'));
  for (const file of files) {
    const src = path.join(sourceDir, file);
    const raw = fs.readFileSync(src, 'utf8');
    try {
      const parsed = JSON.parse(raw);
      const list = Array.isArray(parsed) ? parsed : [];
      reportsData[file] = list;
      allAlerts = allAlerts.concat(list);
      availableReports.push({ id: file, label: formatLabel(file) });
    } catch (_) {
      reportsData[file] = [];
      availableReports.push({ id: file, label: file });
    }
  }
}

// Add aggregated report
if (allAlerts.length > 0) {
  const aggregatedId = 'all_alerts_aggregated.json';
  reportsData[aggregatedId] = allAlerts;
  availableReports.unshift({ id: aggregatedId, label: '📂 All Alerts (Aggregated)' });
}

const outDir = path.dirname(outPath);
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(
  outPath,
  '// Generato da scripts/sync-alerts.js – non modificare a mano\n' +
  `export const availableReports = ${JSON.stringify(availableReports)};\n` +
  `export const reportsData = ${JSON.stringify(reportsData)};\n`,
  'utf8'
);
console.log('sync-alerts: scritto', outPath, '(', availableReports.length, 'report )');
