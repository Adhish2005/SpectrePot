/**
 * SpectrePot 3D — Attacker Session Replay Engine
 * Plays back recorded keystrokes and outputs in a cyber terminal.
 */

class SessionReplayer {
    constructor() {
        this.currentSession = null;
        this.isPlaying = false;
        this.timer = null;
        this.speed = 1.0;
        this.currentIndex = 0;
        this.terminalEl = null;
    }

    init() {
        this.terminalEl = document.getElementById('replayTerminal');
    }

    async loadSessionsList() {
        try {
            const resp = await fetch('/api/sessions');
            const sessions = await resp.json();
            const listEl = document.getElementById('sessionsList');
            if (!listEl) return;

            if (sessions.length === 0) {
                listEl.innerHTML = '<div class="empty-sessions">No interactive terminal sessions recorded yet. Launch an SSH/Telnet attack to record a session!</div>';
                return;
            }

            listEl.innerHTML = sessions.map(s => `
                <div class="session-item" onclick="sessionReplayer.playSession('${s.session_id}')">
                    <div class="session-item-header">
                        <span class="badge ${s.protocol.toLowerCase()}">${s.protocol}</span>
                        <span class="session-ip">${s.source_ip}</span>
                        <span class="session-cmds">${s.command_count} cmds</span>
                    </div>
                    <div class="session-item-footer">
                        <span>User: ${s.username || 'anonymous'}</span>
                        <span>${new Date(s.start_time * 1000).toLocaleTimeString()}</span>
                    </div>
                </div>
            `).join('');
        } catch (e) {
            console.error('Failed to load sessions:', e);
        }
    }

    async playSession(sessionId) {
        this.stop();
        try {
            const resp = await fetch(`/api/sessions/${sessionId}`);
            const data = await resp.json();
            if (!data || !data.events) return;

            this.currentSession = data;
            this.currentIndex = 0;
            this.isPlaying = true;

            // Update Metadata Header
            document.getElementById('replaySessionId').textContent = sessionId.substring(0, 8);
            document.getElementById('replayIp').textContent = data.source_ip;
            document.getElementById('replayProto').textContent = data.protocol;
            document.getElementById('replayUser').textContent = data.username || 'unknown';

            // Clear terminal screen
            if (this.terminalEl) {
                this.terminalEl.innerHTML = '';
            }

            // Open Modal
            document.getElementById('replayerModal').classList.add('active');

            // Begin Playback
            this._runPlaybackStep();
        } catch (e) {
            console.error('Error opening session:', e);
        }
    }

    _runPlaybackStep() {
        if (!this.isPlaying || !this.currentSession || this.currentIndex >= this.currentSession.events.length) {
            this.isPlaying = false;
            this._updatePlayButton();
            return;
        }

        const events = this.currentSession.events;
        const currentEvent = events[this.currentIndex];
        
        // Append text to terminal
        this._renderTerminalChunk(currentEvent);

        this.currentIndex++;

        // Calculate delay to next event
        let delay = 300;
        if (this.currentIndex < events.length) {
            const nextEvent = events[this.currentIndex];
            const timeDiff = (nextEvent.t - currentEvent.t) * 1000;
            // Cap idle delays to 1.5s max for smooth viewing
            delay = Math.min(1500, Math.max(50, timeDiff)) / this.speed;
        }

        this.timer = setTimeout(() => {
            this._runPlaybackStep();
        }, delay);
    }

    _renderTerminalChunk(event) {
        if (!this.terminalEl) return;
        
        const chunk = document.createElement('span');
        if (event.type === 'in') {
            chunk.className = 'term-input';
            chunk.textContent = event.data + '\n';
        } else {
            chunk.className = 'term-output';
            chunk.textContent = event.data;
        }

        this.terminalEl.appendChild(chunk);
        this.terminalEl.scrollTop = this.terminalEl.scrollHeight;
    }

    togglePlayPause() {
        if (this.isPlaying) {
            this.pause();
        } else {
            this.resume();
        }
    }

    pause() {
        this.isPlaying = false;
        if (this.timer) clearTimeout(this.timer);
        this._updatePlayButton();
    }

    resume() {
        if (!this.currentSession) return;
        this.isPlaying = true;
        this._updatePlayButton();
        this._runPlaybackStep();
    }

    restart() {
        this.pause();
        this.currentIndex = 0;
        if (this.terminalEl) this.terminalEl.innerHTML = '';
        this.resume();
    }

    setSpeed(speedVal) {
        this.speed = parseFloat(speedVal);
        document.querySelectorAll('.btn-speed').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.speed == speedVal);
        });
    }

    stop() {
        this.isPlaying = false;
        if (this.timer) clearTimeout(this.timer);
        this.currentIndex = 0;
        this._updatePlayButton();
    }

    closeModal() {
        this.stop();
        document.getElementById('replayerModal').classList.remove('active');
    }

    _updatePlayButton() {
        const btn = document.getElementById('playPauseBtn');
        if (btn) {
            btn.innerHTML = this.isPlaying ? 'Pause' : 'Play';
        }
    }
}

window.sessionReplayer = new SessionReplayer();

