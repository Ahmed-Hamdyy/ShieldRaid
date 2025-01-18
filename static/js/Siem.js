// Initialize logger
const logger = {
    debug: (message) => console.debug(`[DEBUG] ${message}`),
    info: (message) => console.log(`[INFO] ${message}`),
    error: (message, error) => console.error(`[ERROR] ${message}`, error)
};

class EventMonitor {
    constructor() {
        logger.info('Initializing EventMonitor');
        
        // Initialize elements
        this.initializeElements();
        
        // Initialize state
        this.isMonitoring = false;
        this.pollInterval = null;
        this.expandedCards = new Map(); // Store expanded state of cards
        this.currentEvents = []; // Store the current events
        this.currentAlerts = []; // Store the current alerts

        // Set up event listeners
        this.setupEventListeners();
        
        // Load initial data
        this.loadInitialData();
        
        logger.info('EventMonitor initialization complete');
    }

    initializeElements() {
        logger.info('Initializing DOM elements');
        
        // Get all required DOM elements
        const elements = {
            eventContainer: 'eventContainer',
            alertContainer: 'alertContainer',
            startButton: 'startButton',
            clearButton: 'clearButton',
            monitorStatus: 'monitorStatus',
            statusText: 'statusText',
            logTypeFilter: 'logTypeFilter',
            eventIdFilter: 'eventIdFilter',
            sourceFilter: 'sourceFilter'
        };

        // Initialize each element and log its status
        for (const [key, id] of Object.entries(elements)) {
            this[key] = document.getElementById(id);
            if (this[key]) {
                logger.info(`Found ${key} element`);
            } else {
                logger.error(`Failed to find ${key} element with ID: ${id}`);
            }
        }
    }

    setupEventListeners() {
        logger.info('Setting up event listeners');

        // Start button
        if (this.startButton) {
            this.startButton.addEventListener('click', () => {
                logger.info('Start button clicked');
                this.handleStartClick();
            });
            logger.info('Start button listener set up');
        } else {
            logger.error('Start button not found');
        }

        // Clear button
        if (this.clearButton) {
            this.clearButton.addEventListener('click', () => {
                logger.info('Clear button clicked');
                this.handleClearClick();
            });
            logger.info('Clear button listener set up');
        } else {
            logger.error('Clear button not found');
        }

        // Filters
        const setupFilterListener = (element, eventType, name) => {
            if (element) {
                element.addEventListener(eventType, () => {
                    logger.info(`${name} filter changed`);
                    this.applyFilters();
                });
                logger.info(`${name} filter listener set up`);
            } else {
                logger.error(`${name} filter not found`);
            }
        };

        setupFilterListener(this.logTypeFilter, 'change', 'Log type');
        setupFilterListener(this.eventIdFilter, 'input', 'Event ID');
        setupFilterListener(this.sourceFilter, 'input', 'Source');
    }

    applyFilters() {
        const logType = this.logTypeFilter.value;
        const eventId = this.eventIdFilter.value.trim();
        const source = this.sourceFilter.value.trim().toLowerCase();

        // Filter events
        const filteredEvents = this.currentEvents.filter(event => {
            const matchLogType = !logType || event.log_type === logType;
            const matchEventId = !eventId || event.event_id.toString() === eventId;
            const matchSource = !source || event.source.toLowerCase().includes(source);
            return matchLogType && matchEventId && matchSource;
        });

        // Filter alerts
        const filteredAlerts = this.currentAlerts.filter(alert => {
            const matchLogType = !logType || alert.log_type === logType;
            const matchEventId = !eventId || alert.event_id.toString() === eventId;
            const matchSource = !source || alert.source.toLowerCase().includes(source);
            return matchLogType && matchEventId && matchSource;
        });

        // Update UI with filtered data
        this.updateUIWithFilteredData(filteredEvents, filteredAlerts);
    }

    updateUIWithFilteredData(filteredEvents, filteredAlerts) {
        if (this.eventContainer) {
            this.eventContainer.innerHTML = '';
            if (filteredEvents.length === 0) {
                this.eventContainer.innerHTML = '<div class="empty-state">No events match the current filters</div>';
            } else {
                filteredEvents.forEach(event => {
                    const isExpanded = this.expandedCards.get(`event-${event.event_id}`);
                    const card = this.createEventCard(event, isExpanded);
                    this.eventContainer.appendChild(card);
                });
            }
        }

        if (this.alertContainer) {
            this.alertContainer.innerHTML = '';
            if (filteredAlerts.length === 0) {
                this.alertContainer.innerHTML = '<div class="empty-state">No alerts match the current filters</div>';
            } else {
                filteredAlerts.forEach(alert => {
                    const isExpanded = this.expandedCards.get(`alert-${alert.event_id}`);
                    const card = this.createAlertCard(alert, isExpanded);
                    this.alertContainer.appendChild(card);
                });
            }
        }
    }

    async loadInitialData() {
        try {
            // Load initial events and alerts
            const [eventResponse, alertResponse] = await Promise.all([
                fetch('/siem/events', {
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                }),
                fetch('/siem/alerts', {
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
            ]);

            if (!eventResponse.ok) throw new Error(`HTTP error! status: ${eventResponse.status}`);
            if (!alertResponse.ok) throw new Error(`HTTP error! status: ${alertResponse.status}`);

            this.currentEvents = await eventResponse.json();
            this.currentAlerts = await alertResponse.json();

            // Update UI with initial data
            this.applyFilters();
            logger.info('Initial data loaded successfully');
        } catch (error) {
            logger.error('Error loading initial data:', error);
            this.showNotification('Error loading initial data: ' + error.message, 'error');
        }
    }

    updateStatus(isActive) {
        if (this.statusIndicator && this.statusText) {
            this.statusIndicator.className = `status-indicator ${isActive ? 'status-active' : 'status-inactive'}`;
            this.statusText.textContent = isActive ? 'Monitoring Active' : 'Monitoring Inactive';
            logger.info(`Status updated: ${isActive ? 'Active' : 'Inactive'}`);
        } else {
            logger.error('Status elements not found');
        }
    }

    async handleStartClick() {
        try {
            if (!this.isMonitoring) {
                logger.info('Starting monitoring');
                const response = await fetch('/siem/start_monitoring', {
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                const data = await response.json();
                
                if (data.status === 'success' || data.status === 'info') {
                    this.isMonitoring = true;
                    this.startButton.innerHTML = '<i class="fas fa-stop"></i> Stop Monitoring';
                    this.startButton.classList.remove('btn-primary');
                    this.startButton.classList.add('btn-danger');
                    this.startPolling();
                    this.updateStatus(true);
                    this.showNotification('Monitoring started', 'success');
                    logger.info('Monitoring started successfully');
                } else {
                    throw new Error(data.message || 'Failed to start monitoring');
                }
            } else {
                logger.info('Stopping monitoring');
                const response = await fetch('/siem/stop_monitoring', {
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                const data = await response.json();
                
                if (data.status === 'success') {
                    this.isMonitoring = false;
                    this.startButton.innerHTML = '<i class="fas fa-play"></i> Start Monitoring';
                    this.startButton.classList.remove('btn-danger');
                    this.startButton.classList.add('btn-primary');
                    this.stopPolling();
                    this.updateStatus(false);
                    this.showNotification('Monitoring stopped', 'info');
                    logger.info('Monitoring stopped successfully');
                } else {
                    throw new Error(data.message || 'Failed to stop monitoring');
                }
            }
        } catch (error) {
            logger.error('Error handling start/stop:', error);
            this.showNotification('Error: ' + error.message, 'error');
            this.isMonitoring = false;
            this.updateStatus(false);
            this.startButton.innerHTML = '<i class="fas fa-play"></i> Start Monitoring';
            this.startButton.classList.remove('btn-danger');
            this.startButton.classList.add('btn-primary');
        }
    }

    handleClearClick() {
        logger.info('Clearing all containers');
        try {
            // Clear UI
            if (this.eventContainer) {
                this.eventContainer.innerHTML = '';
            }
            if (this.alertContainer) {
                this.alertContainer.innerHTML = '';
            }

            // Clear expanded cards state
            this.expandedCards.clear();

            // Clear backend storage
            fetch('/siem/clear_all', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (data.status === 'success') {
                    logger.info('Containers and storage cleared successfully');
                    this.showNotification('All events and alerts cleared', 'success');
                } else {
                    throw new Error(data.message || 'Failed to clear storage');
                }
            })
            .catch(error => {
                logger.error('Error clearing storage:', error);
                this.showNotification('Error clearing data: ' + error.message, 'error');
            });

        } catch (error) {
            logger.error('Error clearing containers:', error);
            this.showNotification('Error clearing containers: ' + error.message, 'error');
        }
    }

    startPolling() {
        logger.info('Starting polling');
        this.pollInterval = setInterval(() => this.pollEvents(), 1000);
    }

    stopPolling() {
        logger.info('Stopping polling');
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    async pollEvents() {
        if (!this.isMonitoring) return;

        try {
            // Poll for new events
            const eventResponse = await fetch('/siem/events', {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            if (!eventResponse.ok) throw new Error(`HTTP error! status: ${eventResponse.status}`);
            const events = await eventResponse.json();
            
            // Poll for new alerts
            const alertResponse = await fetch('/siem/alerts', {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            if (!alertResponse.ok) throw new Error(`HTTP error! status: ${alertResponse.status}`);
            const alerts = await alertResponse.json();

            this.updateUI(events, alerts);
        } catch (error) {
            logger.error('Error polling events:', error);
            // Don't show notification for polling errors to avoid spam
        }
    }

    updateUI(events, alerts) {
        // Store the current data
        this.currentEvents = events;
        this.currentAlerts = alerts;
        
        // Apply any active filters
        this.applyFilters();
    }

    createEventCard(event, isExpanded = false) {
        const card = document.createElement('div');
        card.className = 'card mb-3 event-card';
        const cardId = `event-${event.event_id}`;
        card.setAttribute('data-card-id', cardId);
        
        card.innerHTML = `
            <div class="card-header">
                <div>
                    <strong>Event ID: ${event.event_id}</strong>
                    <span class="badge bg-secondary">${event.log_type}</span>
                    <span class="timestamp">${new Date(event.timestamp).toLocaleString()}</span>
                </div>
                <div class="collapse-arrow">
                    <i class="fas fa-chevron-down" style="transform: ${isExpanded ? 'rotate(180deg)' : 'rotate(0deg)'}"></i>
                </div>
            </div>
            <div class="card-body" style="display: ${isExpanded ? 'block' : 'none'}">
                <p class="card-text"><strong>Source:</strong> ${event.source}</p>
                <div class="event-details">
                    ${Object.entries(event.description).map(([key, value]) => `
                        <div class="detail-row">
                            <span class="detail-key">${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</span>
                            <span class="detail-value">${value}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        // Toggle card expansion
        const cardHeader = card.querySelector('.card-header');
        const cardBody = card.querySelector('.card-body');
        const collapseIcon = card.querySelector('.collapse-arrow i');

        cardHeader.addEventListener('click', () => {
            const isExpanded = cardBody.style.display === 'block';
            cardBody.style.display = isExpanded ? 'none' : 'block';
            collapseIcon.style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(180deg)';
            card.classList.toggle('expanded', !isExpanded);
            this.expandedCards.set(cardId, !isExpanded);
        });

        if (isExpanded) {
            card.classList.add('expanded');
        }

        return card;
    }

    createAlertCard(alert, isExpanded = false) {
        const card = document.createElement('div');
        card.className = 'card mb-3 alert-card';
        const cardId = `alert-${alert.event_id}`;
        card.setAttribute('data-card-id', cardId);
        
        card.innerHTML = `
            <div class="card-header">
                <div>
                    <strong>${alert.alert_message}</strong>
                    <span class="badge">${alert.log_type}</span>
                    <span class="timestamp">${new Date(alert.timestamp).toLocaleString()}</span>
                </div>
                <div class="collapse-arrow">
                    <i class="fas fa-chevron-down" style="transform: ${isExpanded ? 'rotate(180deg)' : 'rotate(0deg)'}"></i>
                </div>
            </div>
            <div class="card-body" style="display: ${isExpanded ? 'block' : 'none'}">
                <p class="card-text"><strong>Event ID:</strong> ${alert.event_id}</p>
                <p class="card-text"><strong>Source:</strong> ${alert.source}</p>
                <div class="event-details">
                    ${Object.entries(alert.description).map(([key, value]) => `
                        <div class="detail-row">
                            <span class="detail-key">${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</span>
                            <span class="detail-value">${value}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        // Toggle card expansion
        const cardHeader = card.querySelector('.card-header');
        const cardBody = card.querySelector('.card-body');
        const collapseIcon = card.querySelector('.collapse-arrow i');

        cardHeader.addEventListener('click', () => {
            const isExpanded = cardBody.style.display === 'block';
            cardBody.style.display = isExpanded ? 'none' : 'block';
            collapseIcon.style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(180deg)';
            card.classList.toggle('expanded', !isExpanded);
            this.expandedCards.set(cardId, !isExpanded);
        });

        if (isExpanded) {
            card.classList.add('expanded');
        }

        return card;
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} notification`;
        notification.textContent = message;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
    }
}

// Initialize the event monitor when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.eventMonitor = new EventMonitor();
});


