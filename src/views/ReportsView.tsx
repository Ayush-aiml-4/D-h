import React, { useState } from 'react';
import { Report } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/FeedbackStates';
import { FileText, ArrowRight, Send } from 'lucide-react';

interface ReportsViewProps {
  reports: Report[];
  onSelectReport: (reportId: string) => void;
  onPrepareDisclosure: (report: Report) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  reports,
  onSelectReport,
  onPrepareDisclosure,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('All');

  const filteredReports = reports.filter((r) => {
    if (statusFilter !== 'All' && r.status !== statusFilter) return false;
    return true;
  });

  const getStatusStyle = (st: Report['status']) => {
    switch (st) {
      case 'Ready':
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-700/50';
      case 'Submitted':
        return 'bg-blue-950/80 text-blue-400 border-blue-700/50';
      case 'Accepted':
        return 'bg-purple-950/80 text-purple-400 border-purple-700/50';
      case 'Resolved':
        return 'bg-emerald-900/60 text-emerald-300 border-emerald-600/50';
      default:
        return 'bg-slate-900 text-slate-300 border-slate-700/50';
    }
  };

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
            <FileText className="w-4 h-4" />
            <span>Responsible Disclosure Reports</span>
          </div>
          <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
            Security Reports
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Professional vulnerability disclosures prepared for authorized security contacts.
          </p>
        </div>

        {/* Filter */}
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-slate-900 border border-white/10 rounded-xl px-4 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500/50"
        >
          <option value="All">All Statuses</option>
          <option value="Ready">Ready for Disclosure</option>
          <option value="Submitted">Submitted</option>
          <option value="Resolved">Resolved</option>
          <option value="Draft">Draft</option>
        </select>
      </div>

      {/* Reports List */}
      {filteredReports.length === 0 ? (
        <EmptyState type="reports" />
      ) : (
        <div className="space-y-4">
          {filteredReports.map((report) => (
            <div
              key={report.id}
              className="glass-panel rounded-2xl p-4 sm:p-6 border border-white/10 hover:border-red-500/50 transition-all cursor-pointer group hover:bg-slate-900/90"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 sm:gap-4 mb-3">
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                    <span className="text-xs font-mono uppercase text-slate-400 font-semibold">
                      {report.programName}
                    </span>
                    <SeverityBadge severity={report.severity} />
                    <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getStatusStyle(report.status)}`}>
                      {report.status}
                    </span>
                  </div>

                  <h3 className="text-base sm:text-lg font-bold font-outfit text-slate-100 group-hover:text-red-300 transition-colors">
                    {report.title}
                  </h3>
                </div>

                <div className="flex flex-wrap items-center gap-2 sm:gap-3 shrink-0">
                  {report.status === 'Ready' && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onPrepareDisclosure(report);
                      }}
                      className="px-3.5 sm:px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 font-outfit text-xs font-bold uppercase tracking-wider shadow-[0_0_12px_rgba(220,38,38,0.3)] transition-colors flex items-center gap-1.5"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>PREPARE DISCLOSURE</span>
                    </button>
                  )}

                  <button
                    onClick={() => onSelectReport(report.id)}
                    className="px-3.5 sm:px-4 py-2 rounded-xl bg-slate-900 border border-white/10 text-slate-200 hover:bg-slate-800 font-outfit text-xs font-bold uppercase tracking-wider transition-colors flex items-center gap-1"
                  >
                    <span>VIEW REPORT</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <p className="text-xs text-slate-300 font-sans line-clamp-2 leading-relaxed mb-4">
                {report.summary}
              </p>

              <div className="pt-3 border-t border-white/5 flex flex-wrap items-center justify-between text-xs font-mono text-slate-400 gap-2">
                <span>Target: <span className="text-slate-200">{report.target}</span></span>
                <span>Researcher: <span className="text-slate-200">{report.researcher}</span></span>
                <span>Created: {report.createdAt}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
