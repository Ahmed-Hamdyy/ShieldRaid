class Analytics {
    constructor() {
        this.charts = {};
        console.log('Analytics class initialized');
        this.setupEventListeners();
        this.loadData();
    }

    setupEventListeners() {
        const refreshButton = document.getElementById('refreshButton');
        if (refreshButton) {
            console.log('Refresh button found');
            refreshButton.addEventListener('click', () => this.loadData());
        } else {
            console.log('Refresh button not found');
        }
    }

    async loadData() {
        try {
            console.log('Loading analytics data...');
            const response = await fetch('/siem/get_analytics_data');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            console.log('Data loaded:', data);
            this.updateUI(data);
        } catch (error) {
            console.error('Error loading analytics data:', error);
        }
    }

    updateUI(data) {
        console.log('Updating UI with data:', data);
        // Update summary stats
        const totalEvents = document.getElementById('totalEvents');
        const totalAlerts = document.getElementById('totalAlerts');
        
        if (totalEvents) totalEvents.textContent = data.total_events || 0;
        if (totalAlerts) totalAlerts.textContent = data.total_alerts || 0;

        // Update charts
        if (data.event_distribution) {
            console.log('Updating event distribution chart');
            this.updateEventDistributionChart(data.event_distribution);
        }
        if (data.alert_types) {
            console.log('Updating alert types chart');
            this.updateAlertTypesChart(data.alert_types);
        }
        if (data.command_stats) {
            console.log('Updating command execution chart');
            this.updateCommandExecutionChart(data.command_stats);
        }
    }

    updateEventDistributionChart(data) {
        const ctx = document.getElementById('eventDistributionChart');
        if (!ctx) {
            console.log('Event distribution chart canvas not found');
            return;
        }
        console.log('Found event distribution chart canvas');

        if (this.charts.eventDistribution) {
            console.log('Destroying old event distribution chart');
            this.charts.eventDistribution.destroy();
        }

        const chartData = {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    'rgba(0, 255, 157, 0.6)',
                    'rgba(0, 102, 255, 0.6)',
                    'rgba(255, 0, 255, 0.6)'
                ],
                borderColor: [
                    'rgba(0, 255, 157, 1)',
                    'rgba(0, 102, 255, 1)',
                    'rgba(255, 0, 255, 1)'
                ],
                borderWidth: 1
            }]
        };

        this.charts.eventDistribution = new Chart(ctx, {
            type: 'pie',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'rgba(255, 255, 255, 0.8)'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Event Type Distribution',
                        color: 'rgba(255, 255, 255, 0.8)'
                    }
                }
            }
        });
        console.log('Event distribution chart created');
    }

    updateAlertTypesChart(data) {
        const ctx = document.getElementById('alertTypesChart');
        if (!ctx) {
            console.log('Alert types chart canvas not found');
            return;
        }
        console.log('Found alert types chart canvas');

        if (this.charts.alertTypes) {
            console.log('Destroying old alert types chart');
            this.charts.alertTypes.destroy();
        }

        const chartData = {
            labels: Object.keys(data),
            datasets: [{
                label: 'Number of Alerts',
                data: Object.values(data),
                backgroundColor: 'rgba(0, 255, 157, 0.6)',
                borderColor: 'rgba(0, 255, 157, 1)',
                borderWidth: 1
            }]
        };

        this.charts.alertTypes = new Chart(ctx, {
            type: 'bar',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Alert Types',
                        color: 'rgba(255, 255, 255, 0.8)'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.8)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.8)'
                        }
                    }
                }
            }
        });
        console.log('Alert types chart created');
    }

    updateCommandExecutionChart(data) {
        const ctx = document.getElementById('commandExecutionChart');
        if (!ctx) {
            console.log('Command execution chart canvas not found');
            return;
        }
        console.log('Found command execution chart canvas');

        if (this.charts.commandExecution) {
            console.log('Destroying old command execution chart');
            this.charts.commandExecution.destroy();
        }

        const chartData = {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: [
                    'rgba(0, 255, 157, 0.6)',
                    'rgba(0, 102, 255, 0.6)',
                    'rgba(255, 0, 255, 0.6)',
                    'rgba(255, 102, 0, 0.6)',
                    'rgba(102, 0, 255, 0.6)'
                ],
                borderColor: [
                    'rgba(0, 255, 157, 1)',
                    'rgba(0, 102, 255, 1)',
                    'rgba(255, 0, 255, 1)',
                    'rgba(255, 102, 0, 1)',
                    'rgba(102, 0, 255, 1)'
                ],
                borderWidth: 1
            }]
        };

        this.charts.commandExecution = new Chart(ctx, {
            type: 'doughnut',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'rgba(255, 255, 255, 0.8)'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Command Execution Distribution',
                        color: 'rgba(255, 255, 255, 0.8)'
                    }
                }
            }
        });
        console.log('Command execution chart created');
    }
}

// Initialize analytics when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing Analytics');
    window.analytics = new Analytics();
}); 