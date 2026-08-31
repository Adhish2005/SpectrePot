/**
 * SpectrePot — SOC Telemetry & Analytics Charts
 * Matte, elegant, minimalist styling powered by Chart.js
 */

class AnalyticsDashboard {
    constructor() {
        this.protocolChart = null;
        this.severityChart = null;
        this.portsChart = null;
        this.credsChart = null;
    }

    init() {
        Chart.defaults.color = '#71717a';
        Chart.defaults.font.family = "'JetBrains Mono', monospace, sans-serif";
        Chart.defaults.font.size = 11;

        this._initProtocolChart();
        this._initSeverityChart();
        this._initPortsChart();
        this._initCredsChart();
    }

    _initProtocolChart() {
        const ctx = document.getElementById('protocolChart');
        if (!ctx) return;
        this.protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['SSH', 'HTTP', 'TELNET', 'TCP SCAN'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#38bdf8', '#818cf8', '#a78bfa', '#34d399'],
                    borderColor: '#09090b',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom', 
                        labels: { 
                            boxWidth: 10, 
                            padding: 12,
                            color: '#a1a1aa'
                        } 
                    }
                },
                cutout: '72%'
            }
        });
    }

    _initSeverityChart() {
        const ctx = document.getElementById('severityChart');
        if (!ctx) return;
        this.severityChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['CRIT', 'HIGH', 'MED', 'LOW'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#fb7185', '#f59e0b', '#38bdf8', '#34d399'],
                    borderRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { 
                        beginAtZero: true, 
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#71717a' }
                    },
                    x: { 
                        grid: { display: false },
                        ticks: { color: '#a1a1aa' }
                    }
                }
            }
        });
    }

    _initPortsChart() {
        const ctx = document.getElementById('portsChart');
        if (!ctx) return;
        this.portsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Hits',
                    data: [],
                    backgroundColor: 'rgba(56, 189, 248, 0.45)',
                    borderColor: 'rgba(56, 189, 248, 0.8)',
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { 
                        beginAtZero: true, 
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#71717a' }
                    },
                    y: { 
                        grid: { display: false },
                        ticks: { color: '#a1a1aa' }
                    }
                }
            }
        });
    }

    _initCredsChart() {
        const ctx = document.getElementById('credsChart');
        if (!ctx) return;
        this.credsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attempts',
                    data: [],
                    backgroundColor: 'rgba(167, 139, 250, 0.45)',
                    borderColor: 'rgba(167, 139, 250, 0.8)',
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { 
                        beginAtZero: true, 
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#71717a' }
                    },
                    y: { 
                        grid: { display: false },
                        ticks: { color: '#a1a1aa' }
                    }
                }
            }
        });
    }

    updateStats(stats) {
        if (!stats) return;

        // Update Protocols
        if (this.protocolChart && stats.protocol_counts) {
            const counts = stats.protocol_counts;
            const labels = Object.keys(counts);
            const data = Object.values(counts);
            if (labels.length > 0) {
                this.protocolChart.data.labels = labels;
                this.protocolChart.data.datasets[0].data = data;
                this.protocolChart.update('none');
            }
        }

        // Update Severity
        if (this.severityChart && stats.severity_counts) {
            const sc = stats.severity_counts;
            this.severityChart.data.datasets[0].data = [
                sc.CRITICAL || 0,
                sc.HIGH || 0,
                sc.MEDIUM || 0,
                sc.LOW || 0
            ];
            this.severityChart.update('none');
        }

        // Update Targeted Ports
        if (this.portsChart && stats.top_ports) {
            this.portsChart.data.labels = stats.top_ports.map(p => `:${p.target_port} (${p.service})`);
            this.portsChart.data.datasets[0].data = stats.top_ports.map(p => p.count);
            this.portsChart.update('none');
        }

        // Update Top Credentials
        if (this.credsChart && stats.top_credentials) {
            this.credsChart.data.labels = stats.top_credentials.map(c => `${c.username}:${c.password}`);
            this.credsChart.data.datasets[0].data = stats.top_credentials.map(c => c.count);
            this.credsChart.update('none');
        }
    }
}

window.analyticsDashboard = new AnalyticsDashboard();
