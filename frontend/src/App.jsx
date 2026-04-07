import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radar, ShieldCheck, Terminal, PlaySquare } from 'lucide-react';
import './App.css';

export default function App() {
  const [url, setUrl] = useState('http://demo.testfire.net');
  const [logs, setLogs] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [skipDirs, setSkipDirs] = useState(true);
  const logsEndRef = useRef(null);

  const startScan = (e) => {
    e.preventDefault();
    if (!url) return;
    setLogs([]);
    setScanning(true);

    const sseUrl = `http://localhost:8005/api/scan/stream?url=${encodeURIComponent(url)}&depth=1&threads=10&skip_dirs=${skipDirs}`;
    const eventSource = new EventSource(sseUrl);

    eventSource.onmessage = (event) => {
      const data = event.data;
      if (data === '[WEBPROBE_DONE]') {
        eventSource.close();
        setScanning(false);
        setLogs(prev => [...prev, { text: ">>> SCAN COMPLETE.", type: 'system' }]);
      } else {
        let type = 'info';
        if (data.includes('[ERROR]') || data.includes('Error')) type = 'error';
        if (data.includes('Missing:') || data.includes('Found')) type = 'success';
        
        setLogs(prev => [...prev, { text: data, type }]);
      }
    };

    eventSource.onerror = (err) => {
      console.error(err);
      eventSource.close();
      setScanning(false);
      setLogs(prev => [...prev, { text: ">>> CONNECTION LOST TO BACKEND.", type: 'error' }]);
    };
  };

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="app-container">
      {/* Background orbs */}
      <div className="bg-effects">
        <motion.div className="orb blue" animate={{ scale: [1, 1.2, 1], rotate: [0, 90, 0] }} transition={{ duration: 10, repeat: Infinity }} />
        <motion.div className="orb purple" animate={{ scale: [1, 1.3, 1], rotate: [0, -90, 0] }} transition={{ duration: 12, repeat: Infinity }} />
      </div>

      <header>
        <motion.div initial={{ y: -50, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="header-content">
          <h1>WEBPROBE <span className="accent">NEXUS</span></h1>
          <p>Asynchronous Vulnerability Vector Engine</p>
        </motion.div>
      </header>

      <main>
        <motion.div className="glass-panel input-section" initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}>
          <form onSubmit={startScan} className="scan-form">
            <div className="input-row">
              <input 
                type="text" 
                value={url} 
                onChange={e => setUrl(e.target.value)} 
                placeholder="Target URL..." 
                disabled={scanning}
              />
              <button type="submit" disabled={scanning || !url}>
                {scanning ? <Radar className="spin" size={20} /> : <PlaySquare size={20} />}
                <span>{scanning ? "SCANNING" : "ENGAGE"}</span>
              </button>
            </div>
            <div className="options">
              <label>
                <input type="checkbox" checked={skipDirs} readOnly onClick={() => setSkipDirs(!skipDirs)} disabled={scanning} />
                Skip Directory Brute-Force (Faster)
              </label>
            </div>
          </form>
        </motion.div>

        <AnimatePresence>
          {logs.length > 0 && (
            <motion.div 
              initial={{ opacity: 0, y: 20 }} 
              animate={{ opacity: 1, y: 0 }}
              className="dashboard"
            >
              <div className="radar-status">
                {scanning ? (
                  <div className="radar-visual active">
                     <Radar size={40} className="spin text-cyan" />
                     <h3>ANALYZING ENDPOINTS</h3>
                  </div>
                ) : (
                  <div className="radar-visual complete">
                     <ShieldCheck size={40} className="text-magenta" />
                     <h3>SCAN RESOLVED</h3>
                  </div>
                )}
              </div>

              <div className="terminal glass-panel">
                <div className="term-header">
                  <Terminal size={16} /> <span>LIVE SCAN FEED</span>
                  <div className="dots"><span/><span/><span/></div>
                </div>
                <div className="term-body">
                  {logs.map((l, i) => (
                    <motion.div 
                      key={i} 
                      className={`log-line ${l.type}`}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                    >
                      {l.text}
                    </motion.div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
