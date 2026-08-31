/**
 * SpectrePot 3D — Core Application Controller & WebSocket Client
 */

class SpectrePotApp {
    constructor() {
        this.socket = null;
        this.globe = null;
        this.threatCount = 0;
        this.critCount = 0;
        this.uniqueIps = new Set();
        this.reconnectTimer = null;
    }

    init() {
        console.log('[*] Initializing SpectrePot 3D Operations Center...');

        // 1. Initialize Threat Globe
        this.globe = new ThreatGlobe('globeContainer');
        this.globe.init();

        // 2. Initialize Analytics Charts
        window.analyticsDashboard.init();

        // 3. Initialize Replayer
        window.sessionReplayer.init();

        // 4. Connect WebSocket Stream
        this.connectWebSocket();

        // 5. Fetch Initial State & Historic Attacks
        this.loadInitialStats();
        this.loadRecentAttacks();

        // 6. Setup UI Event Listeners
        this.setupEventListeners();

        // Periodic telemetry refresh
        setInterval(() => this.loadInitialStats(), 10000);
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/threats`;
        
        console.log(`[*] Connecting to Threat WebSocket: ${wsUrl}`);
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
            console.log('[+] WebSocket Connected.');
            document.getElementById('wsStatus').className = 'status-indicator online';
            document.getElementById('wsStatusText').textContent = 'Live Stream Connected';
            if (this.reconnectTimer) {
                clearInterval(this.reconnectTimer);
                this.reconnectTimer = null;
            }
        };

        this.socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleWebSocketMessage(message);
            } catch (e) {
                console.error('Error parsing WS message:', e);
            }
        };

        this.socket.onclose = () => {
            console.warn('[!] WebSocket Disconnected. Retrying in 3s...');
            document.getElementById('wsStatus').className = 'status-indicator offline';
            document.getElementById('wsStatusText').textContent = 'Reconnecting...';
            if (!this.reconnectTimer) {
                this.reconnectTimer = setInterval(() => this.connectWebSocket(), 3000);
            }
        };

        this.socket.onerror = (err) => {
            console.error('WebSocket error:', err);
        };
    }

    handleWebSocketMessage(message) {
        if (message.type === 'INIT_NODE') {
            if (message.node) {
                this.globe.init(message.node);
                document.getElementById('nodeName').textContent = message.node.name;
                document.getElementById('nodeLocation').textContent = `${message.node.city}, ${message.node.country}`;
            }
        } else if (message.type === 'NEW_ATTACK') {
            const attack = message.data;
            this.processNewAttack(attack);
        } else if (message.type === 'DATA_CLEARED') {
            this.handleDataCleared();
        }
    }

    processNewAttack(attack) {
        // 1. Render 3D Globe ballistic arc
        this.globe.addAttackArc(attack);

        // 2. Append to Live Threat Feed
        this.addAttackToFeed(attack);

        // 4. Update HUD Counters
        this.threatCount++;
        if (attack.severity === 'CRITICAL') this.critCount++;
        if (attack.source_ip) this.uniqueIps.add(attack.source_ip);

        document.getElementById('hudTotalAttacks').textContent = this.threatCount;
        document.getElementById('hudCriticalThreats').textContent = this.critCount;
        document.getElementById('hudUniqueIps').textContent = this.uniqueIps.size;

        // 5. Trigger charts refresh if relevant
        this.loadInitialStats();
    }

    addAttackToFeed(attack) {
        const feedBody = document.getElementById('attackFeedBody');
        if (!feedBody) return;

        const row = document.createElement('tr');
        row.className = `attack-row ${attack.severity.toLowerCase()} highlight-pulse`;

        const timeStr = new Date(attack.timestamp * 1000).toLocaleTimeString();
        const payloadSnippet = attack.payload ? attack.payload.replace(/</g, '&lt;').replace(/>/g, '&gt;').substring(0, 45) : '—';

        row.innerHTML = `
            <td class="col-time">${timeStr}</td>
            <td class="col-ip">
                <span class="country-badge">${(attack.geo_country_code || 'XX').toUpperCase()}</span>
                ${attack.source_ip}
            </td>
            <td class="col-country">${attack.geo_city || attack.geo_country}</td>
            <td class="col-proto"><span class="proto-tag ${attack.protocol.toLowerCase()}">${attack.protocol}</span></td>
            <td class="col-target">:${attack.target_port}</td>
            <td class="col-mitre"><span class="mitre-tag">${attack.mitre_id || 'T1046'}</span></td>
            <td class="col-sev"><span class="sev-badge ${attack.severity.toLowerCase()}">${attack.severity}</span></td>
            <td class="col-payload" title="${attack.payload || ''}">${payloadSnippet}</td>
        `;

        feedBody.insertBefore(row, feedBody.firstChild);

        // Keep table size manageable
        while (feedBody.children.length > 60) {
            feedBody.removeChild(feedBody.lastChild);
        }

        setTimeout(() => row.classList.remove('highlight-pulse'), 1500);
    }

    async loadInitialStats() {
        try {
            const resp = await fetch('/api/stats');
            const stats = await resp.json();
            if (!stats) return;

            this.threatCount = stats.total_attacks || 0;
            this.uniqueIps = new Set(Array(stats.unique_ips || 0).fill(0));
            this.critCount = (stats.severity_counts && stats.severity_counts.CRITICAL) || 0;

            document.getElementById('hudTotalAttacks').textContent = this.threatCount;
            document.getElementById('hudCriticalThreats').textContent = this.critCount;
            document.getElementById('hudUniqueIps').textContent = stats.unique_ips || 0;

            window.analyticsDashboard.updateStats(stats);
        } catch (e) {
            console.error('Failed to load stats:', e);
        }
    }

    async loadRecentAttacks() {
        try {
            const resp = await fetch('/api/attacks?limit=25');
            const attacks = await resp.json();
            const feedBody = document.getElementById('attackFeedBody');
            if (feedBody) feedBody.innerHTML = '';
            attacks.reverse().forEach(a => this.addAttackToFeed(a));
        } catch (e) {
            console.error('Failed to load attacks:', e);
        }
    }

    handleDataCleared() {
        this.threatCount = 0;
        this.critCount = 0;
        this.uniqueIps.clear();
        document.getElementById('hudTotalAttacks').textContent = 0;
        document.getElementById('hudCriticalThreats').textContent = 0;
        document.getElementById('hudUniqueIps').textContent = 0;
        document.getElementById('attackFeedBody').innerHTML = '';
        this.loadInitialStats();
    }

    setupEventListeners() {
        // Clear Logs Button
        const clearBtn = document.getElementById('clearLogsBtn');
        if (clearBtn) {
            clearBtn.addEventListener('click', async () => {
                if (confirm('Clear all stored attacks and telemetry history?')) {
                    await fetch('/api/clear', { method: 'POST' });
                }
            });
        }

        // Sessions Drawer Toggle
        const sessionsBtn = document.getElementById('viewSessionsBtn');
        if (sessionsBtn) {
            sessionsBtn.addEventListener('click', () => {
                window.sessionReplayer.loadSessionsList();
                document.getElementById('sessionsDrawer').classList.toggle('active');
            });
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new SpectrePotApp();
    window.app.init();
});

