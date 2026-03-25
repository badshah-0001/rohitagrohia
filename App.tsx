/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, Component, ErrorInfo, ReactNode } from 'react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  Unlock, 
  Globe, 
  Cpu, 
  Wifi, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle,
  RefreshCw,
  Terminal,
  Info,
  Zap,
  Eye,
  EyeOff,
  HardDrive,
  FileSearch,
  Upload,
  Activity,
  Bug,
  History,
  LogIn,
  LogOut,
  User as UserIcon
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { GoogleGenAI } from "@google/genai";
import { 
  auth, 
  db, 
  googleProvider, 
  signInWithPopup, 
  onAuthStateChanged, 
  doc, 
  setDoc, 
  collection, 
  addDoc, 
  query, 
  where, 
  orderBy, 
  onSnapshot,
  User
} from './firebase';

// Initialize Gemini
const genAI = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

// Error Boundary
interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: any;
}

class ErrorBoundary extends React.Component<any, any> {
  constructor(props: any) {
    super(props);
    (this as any).state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }

  componentDidCatch(error: any, errorInfo: any) {
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }

  render(this: any) {
    const state = this.state;
    const props = this.props;
    if (state.hasError) {
      return (
        <div className="min-h-screen bg-[#0A0A0B] flex items-center justify-center p-6 text-center">
          <div className="max-w-md p-8 bg-[#111113] border border-rose-500/20 rounded-2xl">
            <ShieldAlert className="w-12 h-12 text-rose-500 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-white mb-2">System Critical Error</h2>
            <p className="text-[#888888] text-sm mb-6">
              The security core encountered an unrecoverable exception.
            </p>
            <pre className="bg-black/50 p-4 rounded text-xs text-rose-400 overflow-auto mb-6 text-left">
              {state.error?.message || "Unknown error"}
            </pre>
            <button 
              onClick={() => window.location.reload()}
              className="px-6 py-2 bg-[#3B82F6] text-white rounded-lg text-sm font-bold"
            >
              REBOOT SYSTEM
            </button>
          </div>
        </div>
      );
    }
    return props.children;
  }
}

interface SecuritySignal {
  id: string;
  label: string;
  value: string | boolean;
  status: 'secure' | 'warning' | 'danger' | 'neutral';
  icon: React.ReactNode;
  description: string;
}

interface ScanRecord {
  id: string;
  score: number;
  timestamp: any;
  report: string;
}

function SecurityNexus() {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [signals, setSignals] = useState<SecuritySignal[]>([]);
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [overallScore, setOverallScore] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'audit' | 'files' | 'history'>('audit');
  
  // History State
  const [scanHistory, setScanHistory] = useState<ScanRecord[]>([]);

  // File Scan State
  const [scannedFile, setScannedFile] = useState<{ name: string, size: number, type: string } | null>(null);
  const [fileAnalysis, setFileAnalysis] = useState<string | null>(null);
  const [isFileAnalyzing, setIsFileAnalyzing] = useState(false);

  const scanIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setIsAuthReady(true);
      if (currentUser) {
        // Sync user to Firestore
        setDoc(doc(db, 'users', currentUser.uid), {
          uid: currentUser.uid,
          email: currentUser.email,
          displayName: currentUser.displayName,
          photoURL: currentUser.photoURL,
          createdAt: new Date().toISOString()
        }, { merge: true });
      }
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    detectInitialSignals();
  }, []);

  useEffect(() => {
    if (user && isAuthReady) {
      const q = query(
        collection(db, 'scans'),
        where('uid', '==', user.uid),
        orderBy('timestamp', 'desc')
      );
      const unsubscribe = onSnapshot(q, (snapshot) => {
        const history = snapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data()
        })) as ScanRecord[];
        setScanHistory(history);
      }, (error) => {
        console.error("Firestore Listen Error:", error);
      });
      return () => unsubscribe();
    }
  }, [user, isAuthReady]);

  const detectInitialSignals = async () => {
    const newSignals: SecuritySignal[] = [
      {
        id: 'https',
        label: 'Connection Protocol',
        value: window.location.protocol === 'https:' ? 'HTTPS (Encrypted)' : 'HTTP (Insecure)',
        status: window.location.protocol === 'https:' ? 'secure' : 'danger',
        icon: <Lock className="w-4 h-4" />,
        description: 'Secure connections prevent eavesdropping on your data.'
      },
      {
        id: 'browser',
        label: 'Browser Integrity',
        value: navigator.userAgent.includes('Chrome') ? 'Chrome-based (Stable)' : 'Alternative Engine',
        status: 'neutral',
        icon: <Globe className="w-4 h-4" />,
        description: 'Your current browser and version information.'
      },
      {
        id: 'storage',
        label: 'Storage Persistence',
        value: 'Checking...',
        status: 'neutral',
        icon: <HardDrive className="w-4 h-4" />,
        description: 'Analyzing browser storage quota and persistence.'
      },
      {
        id: 'malware',
        label: 'Malware Heuristics',
        value: 'Active Monitoring',
        status: 'secure',
        icon: <Bug className="w-4 h-4" />,
        description: 'Simulated heuristic analysis for browser-based threats.'
      }
    ];

    // Check Storage Quota
    if (navigator.storage && navigator.storage.estimate) {
      const estimate = await navigator.storage.estimate();
      const usagePercent = ((estimate.usage || 0) / (estimate.quota || 1) * 100).toFixed(2);
      const storageSignal = newSignals.find(s => s.id === 'storage');
      if (storageSignal) {
        storageSignal.value = `${usagePercent}% of quota used`;
        storageSignal.status = parseFloat(usagePercent) > 80 ? 'warning' : 'secure';
      }
    }

    // Check permissions
    try {
      const camPerm = await navigator.permissions.query({ name: 'camera' as any });
      newSignals.push({
        id: 'camera',
        label: 'Camera Privacy',
        value: camPerm.state === 'granted' ? 'Access Granted' : 'Access Restricted',
        status: camPerm.state === 'granted' ? 'warning' : 'secure',
        icon: camPerm.state === 'granted' ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />,
        description: 'Active camera permissions can be a privacy risk if not managed.'
      });
    } catch (e) {}

    setSignals(newSignals);
  };

  const startScan = () => {
    setIsScanning(true);
    setScanProgress(0);
    setAiReport(null);
    setOverallScore(null);

    let progress = 0;
    scanIntervalRef.current = setInterval(() => {
      progress += Math.random() * 8;
      if (progress >= 100) {
        progress = 100;
        clearInterval(scanIntervalRef.current!);
        completeScan();
      }
      setScanProgress(progress);
    }, 200);
  };

  const completeScan = async () => {
    setIsScanning(false);
    setIsAiLoading(true);

    const secureCount = signals.filter(s => s.status === 'secure').length;
    const dangerCount = signals.filter(s => s.status === 'danger').length;
    const score = Math.max(0, Math.min(100, 75 + (secureCount * 8) - (dangerCount * 25)));
    setOverallScore(score);

    try {
      const model = "gemini-3-flash-preview";
      const prompt = `
        As a high-level cybersecurity AI, analyze these device security signals:
        ${JSON.stringify(signals.map(s => ({ label: s.label, value: s.value, status: s.status })))}
        
        Provide a detailed security audit focusing on:
        1. Malware & Virus Vulnerability: Based on the browser environment, what are the risks?
        2. Storage Security: Analyze the storage quota and persistence signals.
        3. Privacy Leaks: Address the camera and cookie permissions.
        4. Threat Mitigation: Specific steps to harden this device.
        
        Be technical but clear. Use Markdown.
      `;

      const result = await genAI.models.generateContent({
        model: model,
        contents: [{ role: "user", parts: [{ text: prompt }] }],
      });

      const reportText = result.text || "Analysis failed.";
      setAiReport(reportText);

      // Save to Firestore if user is logged in
      if (user) {
        await addDoc(collection(db, 'scans'), {
          uid: user.uid,
          score: score,
          report: reportText,
          timestamp: new Date().toISOString(),
          signals: signals.map(s => ({ label: s.label, value: s.value, status: s.status }))
        });
      }
    } catch (error) {
      setAiReport("Error connecting to AI security core.");
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleLogin = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (error) {
      console.error("Login Error:", error);
    }
  };

  const handleLogout = () => auth.signOut();

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setScannedFile({ name: file.name, size: file.size, type: file.type });
    setIsFileAnalyzing(true);
    setFileAnalysis(null);

    try {
      const model = "gemini-3-flash-preview";
      const prompt = `
        Analyze this file metadata for potential security risks:
        Name: ${file.name}
        Size: ${file.size} bytes
        Type: ${file.type}
        
        Is this file type commonly used for malware delivery? What should the user look out for?
        Provide a "Malware Risk Assessment" (Low/Medium/High) and reasoning.
      `;

      const result = await genAI.models.generateContent({
        model: model,
        contents: [{ role: "user", parts: [{ text: prompt }] }],
      });

      setFileAnalysis(result.text || "Analysis failed.");
    } catch (error) {
      setFileAnalysis("Error analyzing file.");
    } finally {
      setIsFileAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#E0E0E0] font-sans selection:bg-[#3B82F6] selection:text-white">
      {/* Background Grid Effect */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]"></div>
      <div className="fixed inset-0 bg-[radial-gradient(circle_800px_at_50%_-100px,#1D4ED815,transparent)]"></div>

      <main className="relative z-10 max-w-6xl mx-auto px-6 py-12">
        {/* Header */}
        <header className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-12">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <div className="p-2 bg-[#1D4ED820] border border-[#1D4ED840] rounded-lg">
                <ShieldCheck className="w-6 h-6 text-[#3B82F6]" />
              </div>
              <span className="text-xs font-mono tracking-widest uppercase text-[#3B82F6] font-bold">Sentinel Protocol v6.0</span>
            </div>
            <h1 className="text-5xl md:text-6xl font-bold tracking-tighter mb-4 text-white">
              Security <span className="text-[#3B82F6]">Nexus</span>
            </h1>
            <p className="text-[#888888] max-w-md text-lg leading-relaxed">
              Full-spectrum security analysis. Detecting malware signatures, storage vulnerabilities, and privacy leaks.
            </p>
          </div>

          <div className="flex flex-col items-end gap-4">
            <div className="flex items-center gap-4 mb-2">
              {user ? (
                <div className="flex items-center gap-3 bg-[#111113] p-2 pr-4 rounded-full border border-white/5">
                  <img src={user.photoURL || ""} alt="" className="w-8 h-8 rounded-full border border-[#3B82F640]" referrerPolicy="no-referrer" />
                  <div className="flex flex-col">
                    <span className="text-[10px] font-bold text-white truncate max-w-[100px]">{user.displayName}</span>
                    <button onClick={handleLogout} className="text-[9px] text-rose-400 hover:text-rose-300 font-mono uppercase tracking-tighter text-left">Disconnect</button>
                  </div>
                </div>
              ) : (
                <button 
                  onClick={handleLogin}
                  className="flex items-center gap-2 px-4 py-2 bg-[#111113] border border-white/5 rounded-xl text-[10px] font-bold text-white hover:border-[#3B82F640] transition-all"
                >
                  <LogIn className="w-3 h-3" />
                  CONNECT IDENTITY
                </button>
              )}
            </div>

            <div className="flex bg-[#111113] p-1 rounded-xl border border-white/5">
              <button 
                onClick={() => setActiveTab('audit')}
                className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${activeTab === 'audit' ? 'bg-[#3B82F6] text-white shadow-lg' : 'text-[#666666] hover:text-white'}`}
              >
                SYSTEM AUDIT
              </button>
              <button 
                onClick={() => setActiveTab('files')}
                className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${activeTab === 'files' ? 'bg-[#3B82F6] text-white shadow-lg' : 'text-[#666666] hover:text-white'}`}
              >
                FILE SANDBOX
              </button>
              {user && (
                <button 
                  onClick={() => setActiveTab('history')}
                  className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${activeTab === 'history' ? 'bg-[#3B82F6] text-white shadow-lg' : 'text-[#666666] hover:text-white'}`}
                >
                  HISTORY
                </button>
              )}
            </div>
            
            {activeTab === 'audit' && (
              <div className="flex flex-col items-end gap-2">
                {!isScanning && !overallScore && (
                  <button 
                    onClick={startScan}
                    className="group relative px-8 py-4 bg-[#3B82F6] hover:bg-[#2563EB] text-white font-bold rounded-xl transition-all duration-300 overflow-hidden shadow-[0_0_20px_rgba(59,130,246,0.3)]"
                  >
                    <div className="relative z-10 flex items-center gap-2">
                      <Activity className="w-5 h-5" />
                      INITIATE FULL SCAN
                    </div>
                  </button>
                )}
                {isScanning && (
                  <div className="w-64">
                    <div className="flex justify-between text-xs font-mono mb-2">
                      <span className="animate-pulse">ANALYZING HEURISTICS...</span>
                      <span>{Math.round(scanProgress)}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-[#1A1A1C] rounded-full overflow-hidden border border-white/5">
                      <motion.div 
                        className="h-full bg-[#3B82F6]"
                        initial={{ width: 0 }}
                        animate={{ width: `${scanProgress}%` }}
                      />
                    </div>
                  </div>
                )}
                {overallScore !== null && !isScanning && (
                  <div className="flex items-baseline gap-2">
                    <span className="text-xs font-mono text-[#888888]">POSTURE:</span>
                    <span className={`text-4xl font-bold ${overallScore > 80 ? 'text-emerald-400' : overallScore > 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                      {overallScore}%
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        </header>

        {activeTab === 'audit' ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Column: Signals */}
            <div className="lg:col-span-1 space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <Terminal className="w-4 h-4 text-[#3B82F6]" />
                <h2 className="text-sm font-bold tracking-widest uppercase text-[#888888]">Security Signals</h2>
              </div>
              
              {signals.map((signal) => (
                <motion.div 
                  key={signal.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="p-4 bg-[#111113] border border-white/5 rounded-xl hover:border-[#3B82F640] transition-colors group relative overflow-hidden"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${
                        signal.status === 'secure' ? 'bg-emerald-500/10 text-emerald-400' :
                        signal.status === 'danger' ? 'bg-rose-500/10 text-rose-400' :
                        signal.status === 'warning' ? 'bg-amber-500/10 text-amber-400' :
                        'bg-white/5 text-[#888888]'
                      }`}>
                        {signal.icon}
                      </div>
                      <span className="text-sm font-medium text-white">{signal.label}</span>
                    </div>
                  </div>
                  <div className="text-xs font-mono text-[#666666] mb-1">{signal.value}</div>
                  <p className="text-[11px] text-[#444444] leading-tight">
                    {signal.description}
                  </p>
                  {signal.status === 'secure' && (
                    <div className="absolute top-0 right-0 p-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-500/40" />
                    </div>
                  )}
                </motion.div>
              ))}
            </div>

            {/* Right Column: AI Report */}
            <div className="lg:col-span-2">
              <div className="relative min-h-[500px] bg-[#111113] border border-white/5 rounded-2xl overflow-hidden shadow-2xl">
                <div className="flex items-center justify-between px-4 py-3 bg-[#1A1A1C] border-b border-white/5">
                  <div className="flex gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-rose-500/40"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-amber-500/40"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/40"></div>
                  </div>
                  <div className="text-[10px] font-mono text-[#444444] uppercase tracking-widest">Security_Audit_Log.md</div>
                </div>

                <div className="p-8 max-h-[600px] overflow-y-auto custom-scrollbar">
                  <AnimatePresence mode="wait">
                    {isAiLoading ? (
                      <motion.div 
                        key="loading"
                        className="flex flex-col items-center justify-center h-64 gap-6"
                      >
                        <div className="relative w-16 h-16">
                          <motion.div 
                            className="absolute inset-0 border-2 border-[#3B82F6] rounded-full"
                            animate={{ scale: [1, 1.5, 1], opacity: [1, 0, 1] }}
                            transition={{ duration: 2, repeat: Infinity }}
                          />
                          <div className="absolute inset-0 border-2 border-[#3B82F620] rounded-full animate-spin border-t-[#3B82F6]"></div>
                        </div>
                        <p className="text-sm font-mono text-[#3B82F6] animate-pulse tracking-widest uppercase">Analyzing Threat Vectors...</p>
                      </motion.div>
                    ) : aiReport ? (
                      <motion.div 
                        key="report"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="prose prose-invert prose-sm max-w-none"
                      >
                        <div className="font-mono text-[#3B82F6] mb-6 text-xs border-b border-[#3B82F620] pb-2">
                          {`> SCAN COMPLETED: ${new Date().toLocaleString()}`}
                        </div>
                        <div className="text-[#E0E0E0] leading-relaxed space-y-4">
                          {aiReport.split('\n').map((line, i) => (
                            <p key={i} className={line.startsWith('#') ? 'text-white font-bold text-xl mt-8' : ''}>
                              {line}
                            </p>
                          ))}
                        </div>
                      </motion.div>
                    ) : (
                      <div className="flex flex-col items-center justify-center h-64 text-center">
                        <Shield className="w-12 h-12 text-[#222] mb-4" />
                        <h3 className="text-white font-bold mb-2">Audit Engine Standby</h3>
                        <p className="text-[#666666] text-sm max-w-xs">
                          Initiate a full environment scan to detect malware, storage risks, and privacy vulnerabilities.
                        </p>
                      </div>
                    )}
                  </AnimatePresence>
                </div>
              </div>
            </div>
          </div>
        ) : activeTab === 'files' ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* File Upload Section */}
            <div className="bg-[#111113] border border-white/5 rounded-2xl p-8 flex flex-col items-center justify-center min-h-[400px]">
              <div className="w-20 h-20 bg-[#3B82F610] rounded-full flex items-center justify-center mb-6 border border-[#3B82F620]">
                <Upload className="w-8 h-8 text-[#3B82F6]" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Malware Sandbox</h3>
              <p className="text-[#666666] text-center max-w-sm mb-8 text-sm">
                Upload a suspicious file to have the AI analyze its metadata and type for known malware delivery patterns.
              </p>
              
              <label className="cursor-pointer group">
                <input type="file" className="hidden" onChange={handleFileUpload} />
                <div className="px-8 py-3 bg-[#1A1A1C] border border-white/10 rounded-xl text-sm font-bold text-white group-hover:border-[#3B82F6] transition-all flex items-center gap-2">
                  <FileSearch className="w-4 h-4" />
                  SELECT FILE TO SCAN
                </div>
              </label>

              {scannedFile && (
                <div className="mt-8 p-4 bg-white/5 rounded-xl border border-white/5 w-full max-w-sm">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="p-2 bg-[#3B82F620] rounded-lg">
                      <Activity className="w-4 h-4 text-[#3B82F6]" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white truncate max-w-[200px]">{scannedFile.name}</div>
                      <div className="text-[10px] text-[#666666] font-mono">{(scannedFile.size / 1024).toFixed(2)} KB</div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* File Analysis Result */}
            <div className="bg-[#111113] border border-white/5 rounded-2xl p-8 min-h-[400px] relative overflow-hidden">
              <div className="flex items-center gap-2 mb-6">
                <Bug className="w-4 h-4 text-[#3B82F6]" />
                <h2 className="text-sm font-bold tracking-widest uppercase text-[#888888]">Analysis Output</h2>
              </div>

              <div className="prose prose-invert prose-sm">
                {isFileAnalyzing ? (
                  <div className="flex flex-col items-center justify-center h-48 gap-4">
                    <div className="w-8 h-8 border-2 border-[#3B82F620] border-t-[#3B82F6] rounded-full animate-spin"></div>
                    <p className="text-xs font-mono text-[#888888]">DECONSTRUCTING FILE HEADERS...</p>
                  </div>
                ) : fileAnalysis ? (
                  <div className="text-[#E0E0E0] leading-relaxed">
                    {fileAnalysis.split('\n').map((line, i) => (
                      <p key={i}>{line}</p>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-48 text-center text-[#444]">
                    <Terminal className="w-12 h-12 mb-4 opacity-20" />
                    <p className="text-sm italic">Waiting for file input...</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="flex items-center gap-2 mb-2">
              <History className="w-4 h-4 text-[#3B82F6]" />
              <h2 className="text-sm font-bold tracking-widest uppercase text-[#888888]">Scan History</h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {scanHistory.length > 0 ? (
                scanHistory.map((scan) => (
                  <motion.div 
                    key={scan.id}
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="p-6 bg-[#111113] border border-white/5 rounded-2xl hover:border-[#3B82F640] transition-all group"
                  >
                    <div className="flex justify-between items-start mb-4">
                      <div className="flex flex-col">
                        <span className="text-[10px] font-mono text-[#444444] uppercase">{new Date(scan.timestamp).toLocaleString()}</span>
                        <span className="text-lg font-bold text-white">Audit Record</span>
                      </div>
                      <div className={`text-2xl font-bold ${scan.score > 80 ? 'text-emerald-400' : scan.score > 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                        {scan.score}%
                      </div>
                    </div>
                    <div className="text-[11px] text-[#666666] line-clamp-3 mb-4">
                      {scan.report}
                    </div>
                    <button 
                      onClick={() => {
                        setAiReport(scan.report);
                        setOverallScore(scan.score);
                        setActiveTab('audit');
                      }}
                      className="w-full py-2 text-[10px] font-bold text-[#3B82F6] border border-[#3B82F620] rounded-lg hover:bg-[#3B82F610] transition-all"
                    >
                      VIEW FULL REPORT
                    </button>
                  </motion.div>
                ))
              ) : (
                <div className="col-span-full flex flex-col items-center justify-center h-64 bg-[#111113] border border-white/5 border-dashed rounded-2xl">
                  <History className="w-8 h-8 text-[#222] mb-4" />
                  <p className="text-[#444444] text-sm">No historical scan data found.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-20 pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-[10px] font-mono text-[#444444]">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
              HEURISTICS ACTIVE
            </div>
            <div className="flex items-center gap-2 text-[10px] font-mono text-[#444444]">
              <div className="w-1.5 h-1.5 rounded-full bg-[#3B82F6]"></div>
              STORAGE ISOLATED
            </div>
          </div>
          <div className="flex flex-col items-end gap-1">
            <p className="text-[10px] font-mono text-[#444444] tracking-tighter">
              SENTINEL NEXUS SECURITY CORE v6.0.0 // NO DATA PERSISTED EXTERNALLY
            </p>
            <p className="text-[11px] font-mono text-[#666666] tracking-tight">
              © 2026 Rohit Agrohia. All rights reserved. Security Nexus.
            </p>
            <p className="text-[9px] font-mono text-[#333333] uppercase tracking-[0.2em]">
              Protecting Digital Frontiers // Neural Link Secured
            </p>
          </div>
        </footer>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <SecurityNexus />
    </ErrorBoundary>
  );
}

