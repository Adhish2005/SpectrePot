/**
 * AttackMe — Flat Geodesic Threat Trajectory Visualizer
 * Professional editorial map powered by Globe.gl & Three.js
 */

class ThreatGlobe {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.globe = null;
        this.arcsData = [];
        this.pointsData = [];
        this.homeNode = {
            lat: 37.7749,
            lng: -122.4194,
            name: "US-West-01",
            color: "#38bdf8"
        };
        this.maxConcurrentArcs = 40;
    }

    init(homeNodeData = null) {
        if (homeNodeData) {
            this.homeNode = {
                lat: homeNodeData.lat,
                lng: homeNodeData.lon,
                name: homeNodeData.name || "Station Node",
                color: "#38bdf8"
            };
        }

        const width = this.container.clientWidth;
        const height = this.container.clientHeight;

        // Initialize Globe.gl instance with flat, clean textures
        this.globe = Globe()
            (this.container)
            .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
            .bumpImageUrl('https://unpkg.com/three-globe/example/img/earth-topology.png')
            .backgroundColor('#000000')
            .width(width)
            .height(height)
            .showAtmosphere(false)
            // Flat geodesic arc trajectories
            .arcColor('color')
            .arcAltitude(d => Math.min(0.4, Math.max(0.12, d.altitude || 0.25)))
            .arcStroke(d => d.stroke || 1.2)
            .arcDashLength(0.9)
            .arcDashGap(1.5)
            .arcDashInitialGap(d => d.initialGap || 0)
            .arcDashAnimateTime(2400)
            .arcLabel(d => `
                <div class="globe-tooltip">
                    <div class="tooltip-header">${d.attack_type}</div>
                    <div><strong>Origin:</strong> ${d.source_ip} (${d.city}, ${d.country})</div>
                    <div><strong>Target:</strong> Port ${d.target_port} / ${d.protocol}</div>
                    <div><strong>Technique:</strong> ${d.mitre_id} (${d.mitre_tactic})</div>
                </div>
            `)
            // Clean pinpoint coordinates
            .pointColor(d => d.color)
            .pointAltitude(d => d.altitude || 0.02)
            .pointRadius(d => d.radius || 0.5)
            .pointLabel(d => d.name);

        // Configure Camera & Subtle Controls
        this.globe.controls().autoRotate = true;
        this.globe.controls().autoRotateSpeed = 0.4;
        this.globe.pointOfView({ lat: 25, lng: 0, altitude: 2.2 });

        // Add persistent Home Station Node Marker
        this.updateHomeNode();

        // Responsive resize listener
        const updateGlobeSize = () => {
            if (this.container && this.globe) {
                const w = this.container.clientWidth || window.innerWidth;
                const h = this.container.clientHeight || 540;
                this.globe.width(w);
                this.globe.height(h);
            }
        };

        window.addEventListener('resize', updateGlobeSize);
        if (window.ResizeObserver) {
            const ro = new ResizeObserver(() => updateGlobeSize());
            ro.observe(this.container);
        }
        setTimeout(updateGlobeSize, 200);
    }

    updateHomeNode() {
        this.pointsData = [
            {
                lat: this.homeNode.lat,
                lng: this.homeNode.lng,
                name: `Station Node: ${this.homeNode.name}`,
                color: '#38bdf8',
                radius: 0.8,
                altitude: 0.03
            }
        ];
        this.globe.pointsData(this.pointsData);
    }

    addAttackArc(event) {
        if (!this.globe) return;

        const srcLat = event.geo_lat || 0;
        const srcLng = event.geo_lon || 0;
        const dstLat = event.dest_lat || this.homeNode.lat;
        const dstLng = event.dest_lon || this.homeNode.lng;

        // Skip if coordinates are invalid or identical
        if (srcLat === 0 && srcLng === 0) return;
        if (Math.abs(srcLat - dstLat) < 0.01 && Math.abs(srcLng - dstLng) < 0.01) return;

        // Flat, professional color classification
        let arcColors = ['#38bdf8', '#34d399'];

        if (event.severity === 'CRITICAL') {
            arcColors = ['#fb7185', '#f43f5e'];
        } else if (event.severity === 'HIGH') {
            arcColors = ['#f59e0b', '#fbbf24'];
        } else if (event.severity === 'MEDIUM') {
            arcColors = ['#38bdf8', '#818cf8'];
        }

        const arcId = 'arc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);

        const arc = {
            id: arcId,
            startLat: srcLat,
            startLng: srcLng,
            endLat: dstLat,
            endLng: dstLng,
            color: arcColors,
            altitude: 0.2 + Math.random() * 0.15,
            stroke: 1.2,
            initialGap: Math.random(),
            source_ip: event.source_ip,
            city: event.geo_city,
            country: event.geo_country,
            target_port: event.target_port,
            protocol: event.protocol,
            severity: event.severity,
            attack_type: event.attack_type,
            mitre_id: event.mitre_id,
            mitre_tactic: event.mitre_tactic,
            createdAt: Date.now()
        };

        // Add origin pinpoint
        const originPoint = {
            id: 'pt_' + arcId,
            lat: srcLat,
            lng: srcLng,
            name: `${event.source_ip} (${event.geo_city || event.geo_country})`,
            color: arcColors[0],
            radius: 0.5,
            altitude: 0.02
        };

        this.arcsData.push(arc);
        this.pointsData.push(originPoint);

        // Keep buffer bounded
        if (this.arcsData.length > this.maxConcurrentArcs) {
            this.arcsData.shift();
        }
        if (this.pointsData.length > this.maxConcurrentArcs + 1) {
            this.pointsData.splice(1, 1);
        }

        this.globe.arcsData([...this.arcsData]);
        this.globe.pointsData([...this.pointsData]);

        // Auto clean-up arc after 12 seconds
        setTimeout(() => {
            this.arcsData = this.arcsData.filter(a => a.id !== arcId);
            this.pointsData = this.pointsData.filter(p => p.id !== 'pt_' + arcId);
            if (this.globe) {
                this.globe.arcsData([...this.arcsData]);
                this.globe.pointsData([...this.pointsData]);
            }
        }, 12000);
    }
}

window.ThreatGlobe = ThreatGlobe;
