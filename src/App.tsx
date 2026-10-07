import React, { useState, useEffect } from 'react';
import {
  NavTab,
  Sidebar,
} from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { StartHuntModal } from './components/StartHuntModal';
import { AddProgramModal } from './components/AddProgramModal';
import { DisclosureModal } from './components/DisclosureModal';
import { Toast, ToastMessage } from './components/Toast';

import {
  initialProfile,
  initialPrograms,
  initialHunts,
  initialFindings,
  initialReports,
  initialAttackSurface,
  initialHistory,
} from './data/mockData';

import {
  Program,
  Hunt,
  Finding,
  Report,
  AssetNode,
  HistorySession,
  UserProfile,
} from './types';

import { api } from './api/client';

import { HomeView } from './views/HomeView';
import { ProgramsView } from './views/ProgramsView';
import { ProgramDetailView } from './views/ProgramDetailView';
import { OperationalReadinessView } from './views/OperationalReadinessView';
import { SecurityProgramOpsView } from './views/SecurityProgramOpsView';
import { SecurityProgramAdminDisclosureView } from './views/SecurityProgramAdminDisclosureView';
import { DevilHuntLiveConsoleView } from './views/DevilHuntLiveConsoleView';
import { ResearchCasesView } from './views/ResearchCasesView';
import { HuntsView } from './views/HuntsView';
import { ActiveHuntView } from './views/ActiveHuntView';
import { AttackSurfaceView } from './views/AttackSurfaceView';
import { CapabilitiesView } from './views/CapabilitiesView';
import { ActiveTestingView } from './views/ActiveTestingView';
import { FindingsView } from './views/FindingsView';
import { FindingDetailView } from './views/FindingDetailView';
import { ReportsView } from './views/ReportsView';
import { ReportDetailView } from './views/ReportDetailView';
import { HistoryView } from './views/HistoryView';
import { SettingsView } from './views/SettingsView';

import {
  getActiveHuntsCount,
  getActionableFindingsCount,
  isActiveHuntStatus,
} from './utils/selectors';

export default function App() {
  // Navigation & UI State
  const [currentTab, setCurrentTab] = useState<NavTab | 'program-detail' | 'active-hunt' | 'finding-detail' | 'report-detail'>('home');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // App Data State
  const [profile, setProfile] = useState<UserProfile>(initialProfile);
  const [programs, setPrograms] = useState<Program[]>(initialPrograms);
  const [hunts, setHunts] = useState<Hunt[]>(initialHunts);
  const [findings, setFindings] = useState<Finding[]>(initialFindings);
  const [reports, setReports] = useState<Report[]>(initialReports);
  const [attackSurface] = useState<AssetNode>(initialAttackSurface);
  const [history, setHistory] = useState<HistorySession[]>(initialHistory);

  // Active Selection IDs
  const [selectedProgramId, setSelectedProgramId] = useState<string>(initialPrograms[0]?.id || '');
  const [selectedHuntId, setSelectedHuntId] = useState<string>(initialHunts[0]?.id || '');
  const [selectedFindingId, setSelectedFindingId] = useState<string>(initialFindings[0]?.id || '');
  const [selectedReportId, setSelectedReportId] = useState<string>(initialReports[0]?.id || '');

  // Modal States
  const [isStartHuntModalOpen, setIsStartHuntModalOpen] = useState(false);
  const [isAddProgramModalOpen, setIsAddProgramModalOpen] = useState(false);
  const [disclosureModalReport, setDisclosureModalReport] = useState<Report | null>(null);

  // Toast Notifications State
  const [toast, setToast] = useState<ToastMessage | null>(null);

  const showToast = (title: string, message?: string, type: 'success' | 'error' | 'info' = 'success') => {
    setToast({ id: `toast-${Date.now()}`, title, message, type });
  };

  // Load initial data from Cloud SQL backend via Express API v1
  useEffect(() => {
    const loadBackendData = async () => {
      try {
        const [progsData, huntsData, findingsData, reportsData, historyData, metricsData] = await Promise.all([
          api.getPrograms().catch(() => null),
          api.getHunts().catch(() => null),
          api.getFindings().catch(() => null),
          api.getReports().catch(() => null),
          api.getHistory().catch(() => null),
          api.getRewardMetrics().catch(() => null),
        ]);

        if (progsData && progsData.length > 0) {
          setPrograms(progsData);
          setSelectedProgramId(progsData[0].id);
        }
        if (huntsData && huntsData.length > 0) {
          setHunts(huntsData);
          setSelectedHuntId(huntsData[0].id);
        }
        if (findingsData && findingsData.length > 0) {
          setFindings(findingsData);
          setSelectedFindingId(findingsData[0].id);
        }
        if (reportsData && reportsData.length > 0) {
          setReports(reportsData);
          setSelectedReportId(reportsData[0].id);
        }
        if (historyData) {
          setHistory(historyData);
        }
        if (metricsData) {
          setProfile((prev) => ({
            ...prev,
            paidBounty: metricsData.formattedPaid,
            pendingBounty: metricsData.formattedPending,
            potentialBounty: metricsData.formattedPotential,
          }));
        }
      } catch (err) {
        console.warn('Backend loading fallback to mock data:', err);
      }
    };

    loadBackendData();
  }, []);

  // Active Selected Item Helpers
  const currentProgram = programs.find((p) => p.id === selectedProgramId) || programs[0];
  const currentHunt = hunts.find((h) => h.id === selectedHuntId) || hunts[0];
  const currentFinding = findings.find((f) => f.id === selectedFindingId) || findings[0];
  const currentReport = reports.find((r) => r.id === selectedReportId) || reports[0];

  const activeHuntCount = getActiveHuntsCount(hunts);
  const actionableCount = getActionableFindingsCount(findings);

  // Handlers — API first, local mock-state fallback when backend/DB is offline
  const handleConfirmStartHunt = async (programId: string, targetDomain: string) => {
    const prog = programs.find((p) => p.id === programId) || programs[0];

    // Prefer existing active session for same target (client-side guard)
    const existing = hunts.find(
      (h) =>
        h.programId === prog.id &&
        h.targetDomain === targetDomain &&
        isActiveHuntStatus(h.status)
    );
    if (existing) {
      setSelectedHuntId(existing.id);
      setCurrentTab('active-hunt');
      showToast('Session Re-entered', `Active hunt session for ${targetDomain} is already running.`);
      return;
    }

    try {
      const res = await api.createHunt(prog.id, targetDomain);
      if (res.isExisting) {
        setSelectedHuntId(res.hunt.id);
        setCurrentTab('active-hunt');
        showToast('Session Re-entered', `Active hunt session for ${targetDomain} is already running.`);
        return;
      }

      setHunts((prev) => [res.hunt, ...prev.filter((h) => h.id !== res.hunt.id)]);
      setSelectedHuntId(res.hunt.id);
      setCurrentTab('active-hunt');
      showToast('Hunt Initialized', `Policy-bounded research session launched on ${targetDomain}`);
    } catch (err: any) {
      // Offline / no-DB fallback: create local hunt session so the UI stays fully interactive
      console.warn('API createHunt unavailable — using local session:', err?.message);
      const localHunt: Hunt = {
        id: `hunt-local-${Date.now()}`,
        programId: prog.id,
        programName: prog.name,
        targetDomain,
        scopeCount: prog.targetCount || 1,
        status: 'Hunting',
        startedAt: 'Just now',
        progressPercent: 12,
        currentTask: 'Reconnaissance & target mapping',
        potentialFindingsCount: 0,
        verifiedFindingsCount: 0,
        policyViolationsCount: 0,
        steps: [
          { id: 's1', name: 'Reconnaissance', status: 'active', progress: 35 },
          { id: 's2', name: 'Target Mapping', status: 'pending' },
          { id: 's3', name: 'API Discovery', status: 'pending' },
          { id: 's4', name: 'Page Analysis', status: 'pending' },
          { id: 's5', name: 'Security Checks', status: 'pending' },
          { id: 's6', name: 'Evidence Validation', status: 'pending' },
        ],
        liveLogs: [
          `Policy enforcer initialized on ${targetDomain}`,
          'Scope boundary checks passed',
          'Starting reconnaissance phase…',
        ],
      };
      setHunts((prev) => [localHunt, ...prev]);
      setSelectedHuntId(localHunt.id);
      setCurrentTab('active-hunt');
      showToast('Hunt Initialized', `Local research session launched on ${targetDomain}`);
    }
  };

  const handleStopHunt = async (huntId: string) => {
    try {
      const updatedHunt = await api.stopHunt(huntId);
      setHunts((prev) => prev.map((h) => (h.id === huntId ? updatedHunt : h)));

      const historyData = await api.getHistory().catch(() => null);
      if (historyData) setHistory(historyData);

      showToast('Hunt Terminated', 'Active session stopped and state recorded');
    } catch (err: any) {
      console.warn('API stopHunt unavailable — local stop:', err?.message);
      setHunts((prev) =>
        prev.map((h) => (h.id === huntId ? { ...h, status: 'Stopped' as const, currentTask: 'Session stopped' } : h))
      );
      const stopped = hunts.find((h) => h.id === huntId);
      if (stopped) {
        setHistory((prev) => [
          {
            id: `hist-local-${Date.now()}`,
            huntId: stopped.id,
            programName: stopped.programName,
            target: stopped.targetDomain,
            date: new Date().toISOString().slice(0, 10),
            duration: stopped.startedAt || '—',
            potentialFindings: stopped.potentialFindingsCount,
            verifiedFindings: stopped.verifiedFindingsCount,
            reportStatus: 'Draft',
            bountyEarned: '—',
          } as HistorySession,
          ...prev,
        ]);
      }
      showToast('Hunt Terminated', 'Session stopped (local mode)');
    }
  };

  const handleAddProgram = (newProg: Program) => {
    setPrograms([newProg, ...programs]);
    showToast('Program Registered', `${newProg.name} added to scope directory`);
  };

  const handleGenerateReport = async (finding: Finding) => {
    try {
      const res = await api.createReport(finding.id);
      setReports((prev) => [res.report, ...prev.filter((r) => r.id !== res.report.id)]);
      setSelectedReportId(res.report.id);
      setCurrentTab('report-detail');
      showToast('Report Generated', `Document created for ${finding.title}`);
    } catch (err: any) {
      console.warn('API createReport unavailable — local report:', err?.message);
      const localReport: Report = {
        id: `rep-local-${Date.now()}`,
        findingId: finding.id,
        programName: finding.programName || 'Program',
        title: finding.title,
        severity: finding.severity,
        researcher: profile.name || 'Ayush (DevilHunt Security)',
        target: finding.target || finding.affectedTarget || 'target',
        status: 'Draft',
        summary: finding.whatWeFound || 'Auto-generated disclosure draft from verified finding.',
        impact: finding.whyItMatters || 'Under assessment',
        technicalDetails: finding.whatWeFound || 'See evidence package for full technical details.',
        evidenceSnippet: finding.evidence?.responseBodySnippet || 'Evidence captured during authorized testing.',
        reproductionSteps: ['Authenticate within authorized scope', `Target: ${finding.target}`, 'Reproduce using attached evidence request'],
        recommendedFix: finding.recommendedFix || 'Pending researcher recommendations',
        testingPolicy: 'Testing performed within program guidelines. No destructive actions.',
        timeline: [
          { date: new Date().toISOString().slice(0, 16).replace('T', ' '), action: 'Report draft generated locally' },
        ],
        createdAt: new Date().toISOString().slice(0, 10),
        recipientContact: 'security@example.test',
      };
      setReports((prev) => [localReport, ...prev]);
      setSelectedReportId(localReport.id);
      setCurrentTab('report-detail');
      showToast('Report Generated', `Local draft created for ${finding.title}`);
    }
  };

  const handleConfirmDisclosure = async (reportId: string) => {
    try {
      const updatedReport = await api.submitReport(reportId);
      setReports((prev) => prev.map((r) => (r.id === reportId ? updatedReport : r)));

      const freshFindings = await api.getFindings().catch(() => null);
      if (freshFindings) setFindings(freshFindings);

      showToast('Report Submitted', `Responsible disclosure bundle sent for ${updatedReport.target}`);
    } catch (err: any) {
      console.warn('API submitReport unavailable — local submit:', err?.message);
      setReports((prev) =>
        prev.map((r) => (r.id === reportId ? { ...r, status: 'Submitted' as const } : r))
      );
      const rep = reports.find((r) => r.id === reportId);
      showToast('Report Submitted', `Disclosure marked submitted for ${rep?.target || 'target'} (local mode)`);
    }
  };

  return (
    <div className="min-h-screen bg-[#090A0F] text-slate-100 flex font-sans antialiased selection:bg-red-900/40 selection:text-red-200">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab as NavTab}
        onSelectTab={(tab) => setCurrentTab(tab)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        actionableCount={actionableCount}
        activeHuntCount={activeHuntCount}
      />

      {/* Main Container Area */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ${
          sidebarCollapsed ? 'ml-18' : 'ml-64'
        }`}
      >
        {/* Top Header */}
        <TopBar
          onStartHuntClick={() => setIsStartHuntModalOpen(true)}
          onNavigate={(tab) => setCurrentTab(tab)}
          onNavigateEntity={(type, id) => {
            if (type === 'program') {
              setSelectedProgramId(id);
              setCurrentTab('program-detail');
            } else if (type === 'hunt') {
              setSelectedHuntId(id);
              setCurrentTab('active-hunt');
            } else if (type === 'finding') {
              setSelectedFindingId(id);
              setCurrentTab('finding-detail');
            } else if (type === 'report') {
              setSelectedReportId(id);
              setCurrentTab('report-detail');
            } else if (type === 'history') {
              setCurrentTab('history');
            }
          }}
          programs={programs}
          hunts={hunts}
          findings={findings}
          reports={reports}
          history={history}
          activeHuntCount={activeHuntCount}
        />

        {/* Dynamic View Body */}
        <main className="flex-1 p-6 sm:p-8 max-w-7xl w-full mx-auto">
          {currentTab === 'home' && (
            <HomeView
              profile={profile}
              hunts={hunts}
              findings={findings}
              programs={programs}
              reports={reports}
              history={history}
              onStartHuntClick={() => setIsStartHuntModalOpen(true)}
              onSelectHunt={(hId) => {
                setSelectedHuntId(hId);
                setCurrentTab('active-hunt');
              }}
              onSelectFinding={(fId) => {
                setSelectedFindingId(fId);
                setCurrentTab('finding-detail');
              }}
              onSelectProgram={(pId) => {
                setSelectedProgramId(pId);
                setCurrentTab('program-detail');
              }}
              onNavigateTab={(tab) => setCurrentTab(tab)}
            />
          )}

          {currentTab === 'programs' && (
            <ProgramsView
              programs={programs}
              onSelectProgram={(pId) => {
                setSelectedProgramId(pId);
                setCurrentTab('program-detail');
              }}
              onOpenAddProgramModal={() => setIsAddProgramModalOpen(true)}
              onStartHuntForProgram={(pId) => {
                setSelectedProgramId(pId);
                setIsStartHuntModalOpen(true);
              }}
            />
          )}

          {currentTab === 'operational-readiness' && <OperationalReadinessView />}
          {currentTab === 'security-program-ops' && <SecurityProgramOpsView />}
          {currentTab === 'security-program-admin' && <SecurityProgramAdminDisclosureView />}
          {currentTab === 'devil-hunt-live' && <DevilHuntLiveConsoleView />}

          {currentTab === 'program-detail' && currentProgram && (
            <ProgramDetailView
              program={currentProgram}
              onBack={() => setCurrentTab('programs')}
              onStartHunt={(progId, targetDomain) => {
                handleConfirmStartHunt(progId, targetDomain);
              }}
            />
          )}

          {currentTab === 'cases' && <ResearchCasesView />}

          {currentTab === 'hunts' && (
            <HuntsView
              hunts={hunts}
              findings={findings}
              onSelectHunt={(hId) => {
                setSelectedHuntId(hId);
                setCurrentTab('active-hunt');
              }}
              onStartHuntClick={() => setIsStartHuntModalOpen(true)}
            />
          )}

          {currentTab === 'active-hunt' && currentHunt && (
            <ActiveHuntView
              hunt={currentHunt}
              findings={findings}
              onBack={() => setCurrentTab('hunts')}
              onViewFindings={() => setCurrentTab('findings')}
              onSelectFinding={(fId) => {
                setSelectedFindingId(fId);
                setCurrentTab('finding-detail');
              }}
              onStopHunt={handleStopHunt}
            />
          )}

          {currentTab === 'attack-surface' && (
            <AttackSurfaceView attackSurface={attackSurface} />
          )}

          {currentTab === 'capabilities' && (
            <CapabilitiesView programs={programs} />
          )}

          {currentTab === 'active-testing' && (
            <ActiveTestingView programs={programs} />
          )}

          {currentTab === 'findings' && (
            <FindingsView
              findings={findings}
              onSelectFinding={(fId) => {
                setSelectedFindingId(fId);
                setCurrentTab('finding-detail');
              }}
            />
          )}

          {currentTab === 'finding-detail' && currentFinding && (
            <FindingDetailView
              finding={currentFinding}
              onBack={() => setCurrentTab('findings')}
              onGenerateReport={handleGenerateReport}
              onUpdateFindingStatus={async (findingId, newStatus) => {
                try {
                  let updated: Finding | undefined;
                  if (newStatus === 'Under review' || newStatus === 'Needs review') {
                    updated = await api.reviewFinding(findingId);
                  } else if (newStatus === 'Validated') {
                    updated = await api.validateFinding(findingId);
                  } else if (newStatus === 'Verified') {
                    updated = await api.verifyFinding(findingId);
                  }
                  if (updated) {
                    setFindings((prev) =>
                      prev.map((f) => (f.id === findingId ? updated! : f))
                    );
                  } else {
                    setFindings((prev) =>
                      prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f))
                    );
                  }
                  showToast('Status Updated', `Finding status changed to ${newStatus}`);
                } catch (err: any) {
                  console.warn('API finding transition unavailable — local update:', err?.message);
                  setFindings((prev) =>
                    prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f))
                  );
                  showToast('Status Updated', `Finding status changed to ${newStatus}`);
                }
              }}
              onNavigateToProgram={(programName) => {
                const prog = programs.find((p) => p.name.toLowerCase().includes(programName.toLowerCase()));
                if (prog) {
                  setSelectedProgramId(prog.id);
                  setCurrentTab('program-detail');
                }
              }}
              onNavigateToHunt={(huntId) => {
                const h = hunts.find((hunt) => hunt.id === huntId);
                if (h) {
                  setSelectedHuntId(h.id);
                  setCurrentTab('active-hunt');
                }
              }}
            />
          )}

          {currentTab === 'reports' && (
            <ReportsView
              reports={reports}
              onSelectReport={(rId) => {
                setSelectedReportId(rId);
                setCurrentTab('report-detail');
              }}
              onPrepareDisclosure={(rep) => setDisclosureModalReport(rep)}
            />
          )}

          {currentTab === 'report-detail' && currentReport && (
            <ReportDetailView
              report={currentReport}
              onBack={() => setCurrentTab('reports')}
              onPrepareDisclosure={(rep) => setDisclosureModalReport(rep)}
              onShowToast={showToast}
            />
          )}

          {currentTab === 'history' && <HistoryView history={history} />}

          {currentTab === 'settings' && (
            <SettingsView
              profile={profile}
              onUpdateProfile={(name) => setProfile((p) => ({ ...p, name }))}
              onResetData={() => {
                setPrograms(initialPrograms);
                setHunts(initialHunts);
                setFindings(initialFindings);
                setReports(initialReports);
              }}
              onShowToast={showToast}
            />
          )}
        </main>
      </div>

      {/* Global Modals */}
      <StartHuntModal
        isOpen={isStartHuntModalOpen}
        onClose={() => setIsStartHuntModalOpen(false)}
        programs={programs}
        onConfirmStartHunt={handleConfirmStartHunt}
      />

      <AddProgramModal
        isOpen={isAddProgramModalOpen}
        onClose={() => setIsAddProgramModalOpen(false)}
        onAddProgram={handleAddProgram}
      />

      {disclosureModalReport && (
        <DisclosureModal
          isOpen={!!disclosureModalReport}
          onClose={() => setDisclosureModalReport(null)}
          report={disclosureModalReport}
          onConfirmDisclosure={handleConfirmDisclosure}
        />
      )}

      {/* Global Toast Notification */}
      <Toast toast={toast} onClose={() => setToast(null)} />
    </div>
  );
}
