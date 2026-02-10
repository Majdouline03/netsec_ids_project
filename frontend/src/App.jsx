import React, { useState } from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Activity, Server, RotateCw, ShieldAlert, Target, Zap, FileJson } from 'lucide-react';
import { availableReports, reportsData } from './data/reportsData';

const COLORS = {
  HIGH: '#EF4444',   // Red
  MEDIUM: '#F59E0B', // Orange
  LOW: '#10B981'     // Green
};

export default function App() {
  const [selectedFile, setSelectedFile] = useState(availableReports[0]?.id ?? '');
  const data = (selectedFile && reportsData[selectedFile]) ? reportsData[selectedFile] : [];

  // --- RENDER: NESSUN FILE TROVATO ---
  if (availableReports.length === 0) {
    return (
      <div className="h-screen flex flex-col items-center justify-center bg-gray-50 p-4">
        <div className="bg-white p-8 rounded-lg shadow-lg text-center border-l-4 border-yellow-500 max-w-lg">
          <FileJson className="mx-auto text-yellow-500 mb-4" size={48} />
          <h2 className="text-xl font-bold mb-2 text-gray-800">Nessun Report Trovato</h2>
          <p className="text-gray-600 mb-6">
            Non ho trovato file JSON nella cartella dati. <br/>
            Esegui lo script Python per generare un'analisi.
          </p>
          <div className="bg-gray-100 p-3 rounded text-left text-xs font-mono text-gray-700">
             python src/engine/run_analysis.py
          </div>
          <button onClick={() => window.location.reload()} className="mt-6 bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 flex items-center gap-2 mx-auto">
            <RotateCw size={18} /> Riprova Scansione
          </button>
        </div>
      </div>
    );
  }

  // --- CALCOLI METRICHE ---
  const totalAlerts = data.length;
  const severityCounts = data.reduce((acc, curr) => {
    acc[curr.severity] = (acc[curr.severity] || 0) + 1;
    return acc;
  }, {});
  const chartData = Object.keys(severityCounts).map(key => ({ name: key, value: severityCounts[key] }));

  // KPI Dinamica
  const hasPortsData = data.some(d => d.unique_dst_ports !== undefined);
  let secondaryKpiValue = 0;
  let secondaryKpiLabel = "";
  let SecondaryIcon = Target;

  if (hasPortsData) {
    secondaryKpiLabel = "Max Ports Scanned";
    secondaryKpiValue = data.length > 0 ? Math.max(...data.map(d => d.unique_dst_ports || 0)) : 0;
  } else {
    secondaryKpiLabel = "Unique Targets (IPs)";
    const uniqueTargets = new Set(data.map(d => d.dst_ip).filter(Boolean));
    secondaryKpiValue = uniqueTargets.size;
    SecondaryIcon = Server;
  }

  const ruleCounts = data.reduce((acc, curr) => {
    acc[curr.rule_name] = (acc[curr.rule_name] || 0) + 1;
    return acc;
  }, {});
  const topThreat = Object.keys(ruleCounts).reduce((a, b) => ruleCounts[a] > ruleCounts[b] ? a : b, "N/A");

  // --- DASHBOARD PRINCIPALE ---
  return (
    <div className="p-6 bg-slate-50 min-h-screen font-sans">
      
      {/* HEADER */}
      <div className="flex flex-col md:flex-row justify-between items-center mb-8 bg-white p-4 rounded-xl shadow-sm border border-slate-200">
        <div>
          <h1 className="text-2xl font-bold text-slate-800 flex items-center gap-2">
            <ShieldAlert className="text-blue-600" size={28}/> Security Analytics
          </h1>
          <p className="text-sm text-slate-500 mt-1 ml-9">Offline IDS Dashboard</p>
        </div>
        
        {/* SELETTORE FILE (POPOLATO AUTOMATICAMENTE) */}
        <div className="mt-4 md:mt-0 flex items-center gap-3 bg-slate-100 p-2 rounded-lg border border-slate-200">
          <FileJson size={20} className="text-slate-500 ml-2"/>
          <select 
            value={selectedFile} 
            onChange={(e) => setSelectedFile(e.target.value)}
            className="bg-transparent text-sm font-medium text-slate-700 outline-none cursor-pointer pr-2 min-w-[220px]"
          >
            {availableReports.map(rep => (
              <option key={rep.id} value={rep.id}>{rep.label}</option>
            ))}
          </select>
          <button 
            onClick={() => window.location.reload()} 
            className="bg-white p-2 rounded shadow-sm hover:text-blue-600 transition"
            title="Ricarica (esegui prima: npm run sync-alerts)"
          >
            <RotateCw size={18}/>
          </button>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="text-center py-20 text-gray-400 bg-white rounded-xl border border-dashed border-gray-300">
          <Server size={64} className="mx-auto mb-4 opacity-20"/>
          <p>Il report selezionato è vuoto (nessun alert rilevato).</p>
        </div>
      ) : (
        <>
          {/* KPI CARDS */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-white p-6 rounded-xl shadow-sm border-l-[6px] border-blue-500 relative overflow-hidden">
              <div className="relative z-10">
                <p className="text-slate-500 text-xs font-bold uppercase mb-1">Total Alerts</p>
                <p className="text-4xl font-extrabold text-slate-800">{totalAlerts}</p>
              </div>
              <Activity className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-100" size={80} />
            </div>
            
            <div className="bg-white p-6 rounded-xl shadow-sm border-l-[6px] border-purple-500 relative overflow-hidden">
              <div className="relative z-10">
                <p className="text-slate-500 text-xs font-bold uppercase mb-1">{secondaryKpiLabel}</p>
                <p className="text-4xl font-extrabold text-slate-800">{secondaryKpiValue}</p>
              </div>
              <SecondaryIcon className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-100" size={80} />
            </div>

            <div className="bg-white p-6 rounded-xl shadow-sm border-l-[6px] border-red-500 relative overflow-hidden">
              <div className="relative z-10">
                <p className="text-slate-500 text-xs font-bold uppercase mb-1">Top Threat</p>
                <p className="text-xl font-bold text-slate-800 truncate max-w-[180px]" title={topThreat}>{topThreat}</p>
              </div>
              <Zap className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-100" size={80} />
            </div>
          </div>

          {/* GRAPHS & TABLES */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="bg-white p-6 rounded-xl shadow-sm lg:col-span-1 flex flex-col">
              <h3 className="font-bold text-slate-700 mb-6 pb-2 border-b border-slate-100">Severity Distribution</h3>
              <div className="flex-grow min-h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={chartData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={5} dataKey="value">
                      {chartData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#94a3b8'} />)}
                    </Pie>
                    <Tooltip />
                    <Legend verticalAlign="bottom" />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-white p-6 rounded-xl shadow-sm lg:col-span-2 flex flex-col h-[500px]">
              <h3 className="font-bold text-slate-700 mb-4 pb-2 border-b border-slate-100 flex justify-between">
                <span>Attack Logs</span>
                <span className="text-xs font-normal text-slate-400 self-end">Showing {data.length} entries</span>
              </h3>
              <div className="overflow-auto flex-grow rounded-lg border border-slate-100">
                <table className="min-w-full text-left text-sm">
                  <thead className="bg-slate-50 text-slate-500 font-medium sticky top-0 z-10">
                    <tr>
                      <th className="p-4">Time</th>
                      <th className="p-4">Source IP</th>
                      <th className="p-4">Type</th>
                      <th className="p-4">Details</th>
                      <th className="p-4 text-center">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {data.map((alert, idx) => (
                      <tr key={idx} className="hover:bg-blue-50/50">
                        <td className="p-4 text-slate-500 whitespace-nowrap text-xs">{new Date(alert.timestamp_start).toLocaleTimeString()}</td>
                        <td className="p-4 font-mono text-blue-600 font-medium">{alert.src_ip}</td>
                        <td className="p-4 text-slate-700 font-semibold">{alert.rule_name}</td>
                        <td className="p-4 text-slate-500 text-xs truncate max-w-[200px]">
                          {alert.unique_dst_ports ? `${alert.unique_dst_ports} ports` : alert.reason || "-"}
                        </td>
                        <td className="p-4 text-center">
                          <span className={`px-2 py-1 rounded-full text-[10px] font-bold ${
                            alert.severity === 'HIGH' ? 'bg-red-100 text-red-700' : 
                            alert.severity === 'MEDIUM' ? 'bg-orange-100 text-orange-700' : 
                            'bg-green-100 text-green-700'
                          }`}>
                            {alert.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}