class CorrelationsManager {
    constructor() {
        this.setupElements();
        this.setupEventListeners();
        this.loadCorrelations();
    }

    setupElements() {
        this.correlationContainer = document.getElementById('correlationResults');
        this.refreshButton = document.getElementById('refreshButton');
        this.timelineContainer = document.getElementById('eventTimeline');
        this.commonPatterns = document.getElementById('commonPatterns');
        this.threatIndicators = document.getElementById('threatIndicators');
    }

    setupEventListeners() {
        if (this.refreshButton) {
            this.refreshButton.addEventListener('click', () => this.loadCorrelations());
        }
    }

    async loadCorrelations() {
        try {
            const response = await fetch('/siem/correlations');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            
            if (data.status === 'success' && data.correlations) {
                this.displayCorrelations(data.correlations);
                this.updateTimeline(data.correlations);
                this.updatePatternAnalysis(data.correlations);
            }
        } catch (error) {
            console.error('Error loading correlations:', error);
            this.showError('Failed to load correlation data');
        }
    }

    displayCorrelations(correlations) {
        if (!this.correlationContainer) return;
        
        this.correlationContainer.innerHTML = '';
        
        if (correlations.length === 0) {
            this.correlationContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-shield-alt"></i>
                    <p>No correlations detected</p>
                </div>
            `;
            return;
        }

        correlations.forEach(correlation => {
            const card = this.createCorrelationCard(correlation);
            this.correlationContainer.appendChild(card);
        });
    }

    createCorrelationCard(correlation) {
        const card = document.createElement('div');
        card.className = 'correlation-card';
        
        const severityClass = this.getSeverityClass(correlation.type);
        const icon = this.getCorrelationIcon(correlation.type);
        
        card.innerHTML = `
            <div class="card-header ${severityClass}">
                <i class="${icon}"></i>
                <h3>${correlation.type}</h3>
                <span class="timestamp">${new Date(correlation.timestamp).toLocaleString()}</span>
            </div>
            <div class="card-body">
                <p class="description">${correlation.details}</p>
                ${this.createSummarySection(correlation.summary)}
                ${this.createEventsSection(correlation.events)}
            </div>
        `;
        
        return card;
    }

    getSeverityClass(type) {
        const severityMap = {
            'Potential Brute Force Attack': 'severity-high',
            'Potential Reconnaissance Activity': 'severity-medium',
            'PowerShell Activity': 'severity-medium',
            'System State Changes': 'severity-low'
        };
        return severityMap[type] || 'severity-low';
    }

    getCorrelationIcon(type) {
        const iconMap = {
            'Potential Brute Force Attack': 'fas fa-user-shield',
            'Potential Reconnaissance Activity': 'fas fa-search',
            'PowerShell Activity': 'fas fa-terminal',
            'System State Changes': 'fas fa-cogs'
        };
        return iconMap[type] || 'fas fa-shield-alt';
    }

    createSummarySection(summary) {
        if (!summary) return '';
        
        return `
            <div class="summary-section">
                <h4>Summary</h4>
                ${Object.entries(summary).map(([key, value]) => `
                    <div class="summary-item">
                        <span class="label">${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</span>
                        <span class="value">${Array.isArray(value) ? value.join(', ') : value}</span>
                    </div>
                `).join('')}
            </div>
        `;
    }

    createEventsSection(events) {
        if (!events || events.length === 0) return '';
        
        return `
            <div class="events-section">
                <h4>Related Events</h4>
                ${events.map(event => `
                    <div class="event-item">
                        <div class="event-header">
                            <span class="event-id">Event ID: ${event.event_id}</span>
                            <span class="event-type">${event.log_type}</span>
                        </div>
                        <div class="event-details">
                            <p>${event.alert_message || 'No alert message'}</p>
                            <span class="event-time">${new Date(event.timestamp).toLocaleString()}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    updateTimeline(correlations) {
        if (!this.timelineContainer) return;
        
        const timelineData = correlations.map(correlation => ({
            timestamp: new Date(correlation.timestamp),
            type: correlation.type,
            details: correlation.details
        })).sort((a, b) => a.timestamp - b.timestamp);

        this.timelineContainer.innerHTML = timelineData.map(event => `
            <div class="timeline-item">
                <div class="timeline-point"></div>
                <div class="timeline-content">
                    <h4>${event.type}</h4>
                    <p>${event.details}</p>
                    <span class="time">${event.timestamp.toLocaleString()}</span>
                </div>
            </div>
        `).join('');
    }

    updatePatternAnalysis(correlations) {
        // Update common patterns
        if (this.commonPatterns) {
            const patterns = this.analyzePatterns(correlations);
            this.commonPatterns.innerHTML = this.createPatternsList(patterns);
        }

        // Update threat indicators
        if (this.threatIndicators) {
            const threats = this.analyzeThreatIndicators(correlations);
            this.threatIndicators.innerHTML = this.createThreatsList(threats);
        }
    }

    analyzePatterns(correlations) {
        const patterns = {};
        correlations.forEach(correlation => {
            patterns[correlation.type] = (patterns[correlation.type] || 0) + 1;
        });
        return patterns;
    }

    analyzeThreatIndicators(correlations) {
        const threats = [];
        correlations.forEach(correlation => {
            if (correlation.summary && correlation.summary.total_attempts > 5) {
                threats.push({
                    type: 'High Frequency Activity',
                    details: `${correlation.type} with ${correlation.summary.total_attempts} attempts`
                });
            }
        });
        return threats;
    }

    createPatternsList(patterns) {
        return Object.entries(patterns)
            .map(([type, count]) => `
                <div class="pattern-item">
                    <span class="pattern-type">${type}</span>
                    <span class="pattern-count">${count}</span>
                </div>
            `).join('');
    }

    createThreatsList(threats) {
        return threats.map(threat => `
            <div class="threat-item">
                <span class="threat-type">${threat.type}</span>
                <p class="threat-details">${threat.details}</p>
            </div>
        `).join('');
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger';
        errorDiv.textContent = message;
        this.correlationContainer.prepend(errorDiv);
        
        setTimeout(() => errorDiv.remove(), 5000);
    }
}

// Initialize the correlations manager when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.correlationsManager = new CorrelationsManager();
}); 