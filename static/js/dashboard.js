// Dashboard Charts
let vulnTypesChart = null;
let severityChart = null;
let trendChart = null;

// Chart color schemes
const CHART_COLORS = {
    severity: {
        critical: '#dc3545',
        high: '#fd7e14',
        medium: '#ffc107',
        low: '#28a745'
    },
    types: [
        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', 
        '#9966FF', '#FF9F40', '#45b7d1', '#96c93d',
        '#e83e8c', '#6f42c1', '#20c997', '#17a2b8'
    ]
};

// Initialize all charts when document is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    fetchDashboardData();
    
    // Update data every minute
    setInterval(fetchDashboardData, 60000);
});

function initializeCharts() {
    // Initialize vulnerability trend chart
    const trendCtx = document.getElementById('vulnerabilityTrend');
    if (trendCtx) {
        trendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Critical',
                        borderColor: CHART_COLORS.severity.critical,
                        backgroundColor: `${CHART_COLORS.severity.critical}20`,
                        data: [],
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'High',
                        borderColor: CHART_COLORS.severity.high,
                        backgroundColor: `${CHART_COLORS.severity.high}20`,
                        data: [],
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Medium',
                        borderColor: CHART_COLORS.severity.medium,
                        backgroundColor: `${CHART_COLORS.severity.medium}20`,
                        data: [],
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Low',
                        borderColor: CHART_COLORS.severity.low,
                        backgroundColor: `${CHART_COLORS.severity.low}20`,
                        data: [],
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            padding: 20
                        }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            label: function(context) {
                                return `${context.dataset.label}: ${context.parsed.y} vulnerabilities`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        },
                        title: {
                            display: true,
                            text: 'Number of Vulnerabilities'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Scan Time'
                        }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                }
            }
        });
    }

    // Initialize vulnerability types chart
    const typesCtx = document.getElementById('vulnTypesChart');
    if (typesCtx) {
        vulnTypesChart = new Chart(typesCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: CHART_COLORS.types,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    // Initialize severity distribution chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        severityChart = new Chart(severityCtx, {
            type: 'pie',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        CHART_COLORS.severity.critical,
                        CHART_COLORS.severity.high,
                        CHART_COLORS.severity.medium,
                        CHART_COLORS.severity.low
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
}

function processVulnerabilities(scan) {
    let vulnerabilities = [];
    try {
        if (typeof scan.vulnerabilities === 'string') {
            vulnerabilities = JSON.parse(scan.vulnerabilities);
        } else if (Array.isArray(scan.vulnerabilities)) {
            vulnerabilities = scan.vulnerabilities;
        } else if (scan.vulnerabilities && typeof scan.vulnerabilities === 'object') {
            vulnerabilities = [scan.vulnerabilities];
        }
    } catch (e) {
        console.warn('Error processing vulnerabilities for scan:', scan.id, e);
    }
    return vulnerabilities;
}

function updateCharts(data) {
    if (!data || !data.scans || !Array.isArray(data.scans)) {
        console.error('Invalid dashboard data format');
        return;
    }

    // Process vulnerability data
    const vulnTypes = {};
    const severityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };
    const timeData = new Map();

    // Sort scans by creation time
    const sortedScans = [...data.scans].sort((a, b) => 
        new Date(a.created_at) - new Date(b.created_at)
    );

    // Process each scan
    sortedScans.forEach(scan => {
        const vulnerabilities = processVulnerabilities(scan);
        const scanTime = new Date(scan.created_at);
        const timeKey = scanTime.toLocaleString([], { 
            hour: '2-digit', 
            minute: '2-digit',
            month: 'short',
            day: 'numeric'
        });

        // Initialize time data if not exists
        if (!timeData.has(timeKey)) {
            timeData.set(timeKey, {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                timestamp: scanTime
            });
        }

        // Process each vulnerability
        vulnerabilities.forEach(vuln => {
            // Count by type
            const type = (vuln.type || 'Unknown').replace(/_/g, ' ');
            vulnTypes[type] = (vulnTypes[type] || 0) + 1;

            // Count by severity
            const severity = (vuln.severity || 'low').toLowerCase();
            if (severityCounts.hasOwnProperty(severity)) {
                severityCounts[severity]++;
                timeData.get(timeKey)[severity]++;
            }
        });
    });

    // Update Vulnerability Types chart
    if (vulnTypesChart) {
        const sortedTypes = Object.entries(vulnTypes)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10); // Show top 10 vulnerability types

        vulnTypesChart.data.labels = sortedTypes.map(([type]) => type);
        vulnTypesChart.data.datasets[0].data = sortedTypes.map(([, count]) => count);
        vulnTypesChart.update();
    }

    // Update Severity Distribution chart
    if (severityChart) {
        severityChart.data.datasets[0].data = [
            severityCounts.critical,
            severityCounts.high,
            severityCounts.medium,
            severityCounts.low
        ];
        severityChart.update();
    }

    // Update Trend chart
    if (trendChart) {
        const sortedTimeData = Array.from(timeData.entries())
            .sort((a, b) => a[1].timestamp - b[1].timestamp);

        trendChart.data.labels = sortedTimeData.map(([time]) => time);
        
        const severityTypes = ['critical', 'high', 'medium', 'low'];
        severityTypes.forEach((severity, index) => {
            trendChart.data.datasets[index].data = sortedTimeData.map(([, data]) => data[severity]);
        });

        trendChart.update();
    }

    // Update statistics
    updateStatistics(data);
}

function updateStatistics(data) {
    const stats = {
        totalScans: data.scans.length,
        totalVulnerabilities: 0,
        successRate: 0,
        avgScanTime: 0,
        criticalVulns: 0
    };

    let successfulScans = 0;
    let totalScanTime = 0;

    data.scans.forEach(scan => {
        const vulnerabilities = processVulnerabilities(scan);
        stats.totalVulnerabilities += vulnerabilities.length;

        // Count critical vulnerabilities
        stats.criticalVulns += vulnerabilities.filter(v => 
            (v.severity || '').toLowerCase() === 'critical'
        ).length;

        if (scan.scan_duration && scan.scan_duration > 0) {
            successfulScans++;
            totalScanTime += scan.scan_duration;
        }
    });

    stats.successRate = stats.totalScans ? (successfulScans / stats.totalScans * 100) : 0;
    stats.avgScanTime = successfulScans ? (totalScanTime / successfulScans) : 0;

    // Update stats in the UI
    const elements = {
        totalScans: document.getElementById('totalScans'),
        totalVulns: document.getElementById('totalVulns'),
        successRate: document.getElementById('successRate'),
        avgScanTime: document.getElementById('avgScanTime'),
        criticalVulns: document.getElementById('criticalVulns')
    };

    if (elements.totalScans) elements.totalScans.textContent = stats.totalScans.toLocaleString();
    if (elements.totalVulns) elements.totalVulns.textContent = stats.totalVulnerabilities.toLocaleString();
    if (elements.successRate) elements.successRate.textContent = `${stats.successRate.toFixed(1)}%`;
    if (elements.avgScanTime) elements.avgScanTime.textContent = `${stats.avgScanTime.toFixed(1)}s`;
    if (elements.criticalVulns) elements.criticalVulns.textContent = stats.criticalVulns.toLocaleString();
}

async function fetchDashboardData() {
    try {
        const response = await fetch('/dashboard_data');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        if (data.error) {
            console.error('Error in dashboard data:', data.error);
            return;
        }

        updateCharts(data);
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
    }
} 