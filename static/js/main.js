document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const scanResults = document.getElementById('scanResults');
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
    const scanStatus = document.getElementById('scanStatus');
    const criticalCount = document.getElementById('criticalCount');
    const highCount = document.getElementById('highCount');
    const mediumCount = document.getElementById('mediumCount');
    const lowCount = document.getElementById('lowCount');
    const securityScore = document.getElementById('securityScore');
    const testsRun = document.getElementById('testsRun');
    const totalIssues = document.getElementById('totalIssues');
    const scanTarget = document.getElementById('scanTarget');

    // Store the latest scan results
    let latestScanResults = null;

    if (!scanForm) {
        console.error('Scan form not found');
        return;
    }

    // Form submission handler
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = document.querySelector('input[name="url"]').value;
        
        // Collect selected modules
        const selectedModules = [];
        document.querySelectorAll('.scan-modules input[type="checkbox"]:checked').forEach(checkbox => {
            selectedModules.push(checkbox.name);
        });
        
        // Show loading state while preserving the results container
        if (scanResults) {
            scanResults.style.display = 'block';
            // Create or update loading container
            let loadingContainer = scanResults.querySelector('.loading-container');
            if (!loadingContainer) {
                loadingContainer = document.createElement('div');
                loadingContainer.className = 'loading-container text-center';
            }
            loadingContainer.innerHTML = `
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Scanning...</span>
                </div>
                <p class="mt-3">Scanning...</p>
            `;
            
            // If vulnerabilitiesList exists, insert loading container before it
            if (vulnerabilitiesList) {
                vulnerabilitiesList.innerHTML = '';
                vulnerabilitiesList.parentNode.insertBefore(loadingContainer, vulnerabilitiesList);
            } else {
                scanResults.appendChild(loadingContainer);
            }
        }
        
        // Reset counters
        if (criticalCount) criticalCount.textContent = '0';
        if (highCount) highCount.textContent = '0';
        if (mediumCount) mediumCount.textContent = '0';
        if (lowCount) lowCount.textContent = '0';
        
        // Start scan
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                url: url,
                modules: selectedModules
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Scan request failed: ${response.status} ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            // Store the latest scan results
            latestScanResults = {
                target_url: url,
                vulnerabilities: data.vulnerabilities || [],
                stats: data.stats || {},
                scan_duration: data.scan_duration || 0
            };

            // Remove loading container
            const loadingContainer = document.querySelector('.loading-container');
            if (loadingContainer) {
                loadingContainer.remove();
            }

            // Update scan duration
            const scanDuration = document.getElementById('scanDuration');
            if (scanDuration) {
                scanDuration.textContent = `(${data.scan_duration || 0}s)`;
            }

            // Update stats if they exist
            const stats = data.stats || {};
            if (criticalCount) criticalCount.textContent = stats.critical || 0;
            if (highCount) highCount.textContent = stats.high || 0;
            if (mediumCount) mediumCount.textContent = stats.medium || 0;
            if (lowCount) lowCount.textContent = stats.low || 0;

            // Update overall stats
            updateStats();

            // Display vulnerabilities
            if (vulnerabilitiesList) {
                vulnerabilitiesList.innerHTML = '';
                
                const vulnerabilities = data.vulnerabilities || [];
                if (vulnerabilities.length === 0) {
                    vulnerabilitiesList.innerHTML = '<div class="alert alert-success">No vulnerabilities found!</div>';
                } else {
                    // Group vulnerabilities by type
                    const groupedVulns = vulnerabilities.reduce((acc, vuln) => {
                        const type = vuln.type || 'Unknown';
                        if (!acc[type]) {
                            acc[type] = [];
                        }
                        acc[type].push(vuln);
                        return acc;
                    }, {});

                    // Sort vulnerability types by highest severity in each group
                    const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
                    const sortedTypes = Object.entries(groupedVulns).sort(([,a], [,b]) => {
                        const severityA = Math.max(...a.map(v => severityOrder[v.severity?.toLowerCase()] || 0));
                        const severityB = Math.max(...b.map(v => severityOrder[v.severity?.toLowerCase()] || 0));
                        return severityB - severityA;
                    });

                    sortedTypes.forEach(([type, vulns], typeIndex) => {
                        const mainVuln = vulns[0];
                        const vulnDiv = document.createElement('div');
                        const severity = mainVuln.severity?.toLowerCase() || 'low';
                        
                        // Add both vulnerability-item class and severity class
                        vulnDiv.className = `vulnerability-item ${severity}`;
                        
                        // Create unique IDs
                        const headerId = `vuln-header-${typeIndex}`;
                        const contentId = `vuln-content-${typeIndex}`;
                        
                        // Create the collapsible header
                        const header = document.createElement('div');
                        header.className = 'vulnerability-header';
                        header.setAttribute('id', headerId);
                        header.setAttribute('data-bs-toggle', 'collapse');
                        header.setAttribute('data-bs-target', `#${contentId}`);
                        header.setAttribute('aria-expanded', 'false');
                        header.setAttribute('aria-controls', contentId);
                        
                        header.innerHTML = `
                            <div class="d-flex justify-content-between align-items-center w-100">
                                <div class="d-flex align-items-center gap-3">
                                    <i class="fas fa-bug"></i>
                                    <div>
                                        <h4 class="mb-0">${type}</h4>
                                        <small class="text-muted">${vulns.length} ${vulns.length === 1 ? 'instance' : 'instances'} found</small>
                                    </div>
                                </div>
                                <div class="d-flex align-items-center gap-3">
                                    <span class="severity ${severity}">${mainVuln.severity || 'Low'}</span>
                                    <i class="fas fa-chevron-down chevron-icon"></i>
                                </div>
                            </div>
                        `;
                        
                        // Create the collapsible content
                        const content = document.createElement('div');
                        content.className = 'collapse';
                        content.id = contentId;
                        
                        // Create content for the main finding
                        let contentHTML = `
                            <div class="vulnerability-content p-4">
                                <div class="main-finding p-3 card rounded">
                                    <div class="d-flex justify-content-between align-items-center mb-3">
                                        <h6 class="mb-0">Primary Finding</h6>
                                        <span class="severity ${severity}">${mainVuln.severity || 'Low'}</span>
                                    </div>
                                    
                                    <div class="description-block mb-3">
                                        <p class="vuln-description mb-0">${mainVuln.description || 'No description available'}</p>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="detail-group mb-3">
                                                <h6 class="detail-title">Location</h6>
                                                <code class="d-block p-2 card rounded">${mainVuln.location || 'N/A'}</code>
                                            </div>
                                            ${mainVuln.method ? `
                                                <div class="detail-group mb-3">
                                                    <h6 class="detail-title">Method</h6>
                                                    <code class="d-block p-2 card rounded">${mainVuln.method}</code>
                                                </div>
                                            ` : ''}
                                        </div>
                                        <div class="col-md-6">
                                            ${mainVuln.parameter ? `
                                                <div class="detail-group mb-3">
                                                    <h6 class="detail-title">Parameter</h6>
                                                    <code class="d-block p-2 card rounded">${mainVuln.parameter}</code>
                                                </div>
                                            ` : ''}
                                            ${mainVuln.payload ? `
                                                <div class="detail-group mb-3">
                                                    <h6 class="detail-title">Payload</h6>
                                                    <code class="d-block p-2 card rounded">${mainVuln.payload}</code>
                                                </div>
                                            ` : ''}
                                        </div>
                                    </div>
                                    
                                    ${mainVuln.evidence ? `
                                        <div class="detail-group mt-2">
                                            <h6 class="detail-title">Evidence</h6>
                                            <pre class="evidence-code p-3 card rounded">${mainVuln.evidence}</pre>
                                        </div>
                                    ` : ''}
                                </div>

                                ${vulns.length > 1 ? `
                                    <div class="additional-findings mt-4">
                                        <div class="d-flex align-items-center gap-2 mb-3">
                                            <button class="btn btn-outline-secondary btn-sm" type="button" 
                                                    data-bs-toggle="collapse" data-bs-target="#additional-${contentId}">
                                                <i class="fas fa-plus-circle me-1"></i>
                                                Additional Findings (${vulns.length - 1})
                                            </button>
                                        </div>
                                        <div class="collapse" id="additional-${contentId}">
                                            <div class="additional-findings-list">
                                                ${vulns.slice(1).map((vuln, i) => `
                                                    <div class="additional-finding-item p-3 card rounded mb-3">
                                                        <div class="d-flex justify-content-between align-items-center mb-3">
                                                            <h6 class="mb-0">Finding #${i + 2}</h6>
                                                            <span class="severity ${vuln.severity?.toLowerCase() || 'low'}">${vuln.severity || 'Low'}</span>
                                                        </div>
                                                        
                                                        <div class="description-block mb-3">
                                                            <p class="vuln-description mb-0">${vuln.description || 'No description available'}</p>
                                                        </div>

                                                        <div class="row">
                                                            <div class="col-md-6">
                                                                <div class="detail-group mb-3">
                                                                    <h6 class="detail-title">Location</h6>
                                                                    <code class="d-block p-2 card rounded card-code">${vuln.location || 'N/A'}</code>
                                                                </div>
                                                                ${vuln.method ? `
                                                                    <div class="detail-group mb-3">
                                                                        <h6 class="detail-title">Method</h6>
                                                                        <code class="d-block p-2 card rounded">${vuln.method}</code>
                                                                    </div>
                                                                ` : ''}
                                                            </div>
                                                            <div class="col-md-6">
                                                                ${vuln.parameter ? `
                                                                    <div class="detail-group mb-3">
                                                                        <h6 class="detail-title">Parameter</h6>
                                                                        <code class="d-block p-2 card rounded">${vuln.parameter}</code>
                                                                    </div>
                                                                ` : ''}
                                                                ${vuln.payload ? `
                                                                    <div class="detail-group mb-3">
                                                                        <h6 class="detail-title">Payload</h6>
                                                                        <code class="d-block p-2 card rounded">${vuln.payload}</code>
                                                                    </div>
                                                                ` : ''}
                                                            </div>
                                                        </div>
                                                        ${vuln.evidence ? `
                                                            <div class="detail-group mt-2">
                                                                <h6 class="detail-title">Evidence</h6>
                                                                <pre class="evidence-code p-3 card rounded">${vuln.evidence}</pre>
                                                            </div>
                                                        ` : ''}
                                                    </div>
                                                `).join('')}
                                            </div>
                                        </div>
                                    </div>
                                ` : ''}

                                ${mainVuln.details ? `
                                    <div class="technical-details mt-4">
                                        <div class="d-flex align-items-center gap-2">
                                            <button class="btn btn-outline-secondary btn-sm" type="button" 
                                                    data-bs-toggle="collapse" data-bs-target="#tech-${contentId}">
                                                <i class="fas fa-code me-1"></i>
                                                Technical Details
                                            </button>
                                        </div>
                                        <div class="collapse mt-3" id="tech-${contentId}">
                                            <pre class="technical-code p-3 card rounded">${JSON.stringify(mainVuln.details, null, 2)}</pre>
                                        </div>
                                    </div>
                                ` : ''}
                            </div>
                        `;

                        content.innerHTML = contentHTML;
                        
                        // Add click handler for the header
                        header.addEventListener('click', () => {
                            const isExpanded = header.getAttribute('aria-expanded') === 'true';
                            header.setAttribute('aria-expanded', !isExpanded);
                        });
                        
                        // Append header and content to the vulnerability item
                        vulnDiv.appendChild(header);
                        vulnDiv.appendChild(content);
                        vulnerabilitiesList.appendChild(vulnDiv);
                    });
                    
                    // Initialize all Bootstrap collapses
                    document.querySelectorAll('.collapse').forEach(collapse => {
                        new bootstrap.Collapse(collapse, {
                            toggle: false
                        });
                    });
                }

                // Add save to database button
                const saveButtonContainer = document.createElement('div');
                saveButtonContainer.className = 'text-center mt-4';
                saveButtonContainer.innerHTML = `
                    <button id="saveToDatabase" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save to Database
                    </button>
                `;
                vulnerabilitiesList.appendChild(saveButtonContainer);

                // Add save to database functionality
                document.getElementById('saveToDatabase').addEventListener('click', function() {
                    if (!latestScanResults) {
                        console.error('No scan results to save');
                        return;
                    }

                    fetch('/save_scan', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(latestScanResults)
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Show success message
                            const successAlert = document.createElement('div');
                            successAlert.className = 'alert alert-success mt-3';
                            successAlert.innerHTML = '<i class="fas fa-check-circle"></i> Scan results saved successfully!';
                            saveButtonContainer.appendChild(successAlert);
                            
                            // Disable save button
                            document.getElementById('saveToDatabase').disabled = true;
                            
                            // Remove success message after 3 seconds
                            setTimeout(() => {
                                successAlert.remove();
                            }, 3000);
                        } else {
                            throw new Error(data.error || 'Failed to save scan results');
                        }
                    })
                    .catch(error => {
                        const errorAlert = document.createElement('div');
                        errorAlert.className = 'alert alert-danger mt-3';
                        errorAlert.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${error.message}`;
                        saveButtonContainer.appendChild(errorAlert);
                        
                        // Remove error message after 3 seconds
                        setTimeout(() => {
                            errorAlert.remove();
                        }, 3000);
                    });
                });
            }

            // Ensure results section stays visible
            if (scanResults) {
                scanResults.style.display = 'block';
            }
        })
        .catch(error => {
            console.error('Scan error:', error);
            // Remove loading container
            const loadingContainer = document.querySelector('.loading-container');
            if (loadingContainer) {
                loadingContainer.remove();
            }
            
            if (vulnerabilitiesList) {
                vulnerabilitiesList.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle"></i>
                        Error: ${error.message}
                    </div>
                `;
            }
            
            // Keep results section visible even on error
            if (scanResults) {
                scanResults.style.display = 'block';
            }
        });
    });

    // Function to update dashboard stats
    function updateStats() {
        fetch('/calculate_stats')
            .then(response => response.json())
            .then(data => {
                // Update stats cards
                document.getElementById('totalScans').textContent = data.total_scans || '0';
                document.getElementById('criticalVulns').textContent = data.critical_vulns || '0';
                document.getElementById('totalVulns').textContent = data.total_vulnerabilities || '0';
                document.getElementById('successRate').textContent = (data.success_rate || '0') + '%';
                document.getElementById('avgScanTime').textContent = (data.average_scan_time || '0') + 's';
            })
            .catch(error => {
                console.error('Error updating stats:', error);
            });
    }

    // Update stats initially and every 30 seconds
    document.addEventListener('DOMContentLoaded', function() {
        updateStats();
        setInterval(updateStats, 30000);
    });

    // Initialize trend chart
    let trendChart = null;

    function initTrendChart() {
        const ctx = document.getElementById('trendChart').getContext('2d');
        trendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Scans',
                        data: [],
                        borderColor: '#4CAF50',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        tension: 0.4,
                        fill: true,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    },
                    {
                        label: 'Vulnerabilities',
                        data: [],
                        borderColor: '#f44336',
                        backgroundColor: 'rgba(244, 67, 54, 0.1)',
                        tension: 0.4,
                        fill: true,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#fff',
                            usePointStyle: true,
                            padding: 20,
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        titleFont: {
                            size: 13
                        },
                        bodyFont: {
                            size: 12
                        },
                        padding: 10,
                        displayColors: true,
                        callbacks: {
                            title: function(context) {
                                return 'Time: ' + context[0].label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        type: 'category',
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#fff',
                            maxRotation: 45,
                            minRotation: 45,
                            font: {
                                size: 11
                            },
                            autoSkip: true,
                            maxTicksLimit: 12
                        },
                        title: {
                            display: true,
                            text: 'Time (Last 24 Hours)',
                            color: '#fff',
                            font: {
                                size: 12
                            }
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)',
                            drawBorder: false
                        },
                        ticks: {
                            color: '#fff',
                            precision: 0,
                            font: {
                                size: 11
                            },
                            stepSize: 1
                        },
                        title: {
                            display: true,
                            text: 'Count',
                            color: '#fff',
                            font: {
                                size: 12
                            }
                        }
                    }
                }
            }
        });
    }

    // Function to update trend chart with new data
    function updateTrendChart(data) {
        if (!trendChart) {
            initTrendChart();
        }

        // Aggregate data by timestamp
        const timeData = {};
        data.forEach(item => {
            const timestamp = item.timestamp; // Using HH:MM format
            if (!timeData[timestamp]) {
                timeData[timestamp] = {
                    scans: 0,
                    vulnerabilities: 0
                };
            }
            timeData[timestamp].scans++;
            timeData[timestamp].vulnerabilities += item.vulnerabilities; // Use the count directly
        });

        // Get sorted timestamps
        const timestamps = Object.keys(timeData).sort((a, b) => {
            const [aHour, aMin] = a.split(':').map(Number);
            const [bHour, bMin] = b.split(':').map(Number);
            return (aHour * 60 + aMin) - (bHour * 60 + bMin);
        });

        // Create datasets
        const scanCounts = timestamps.map(t => timeData[t].scans);
        const vulnCounts = timestamps.map(t => timeData[t].vulnerabilities);

        // Update chart data
        trendChart.data.labels = timestamps;
        trendChart.data.datasets[0].data = scanCounts;
        trendChart.data.datasets[1].data = vulnCounts;

        // Update chart options
        trendChart.options = {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            },
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: '#fff'
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            label += context.parsed.y;
                            return label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#fff'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#fff',
                        stepSize: 1
                    }
                }
            }
        };

        trendChart.update('none');
    }

    // Debounce the stats update to prevent too frequent updates
    const debouncedFetchStats = debounce(fetchStats, 1000);

    // Function to fetch stats data
    async function fetchStats() {
        try {
            const response = await fetch('/calculate_stats');
            const data = await response.json();
            
            // Update stats cards
            document.getElementById('totalScans').textContent = data.total_scans;
            document.getElementById('totalVulns').textContent = data.total_vulnerabilities;
            document.getElementById('successRate').textContent = data.success_rate + '%';
            document.getElementById('avgScanTime').textContent = data.average_scan_time + 's';

            // Update trend chart
            if (data.recent_scans) {
                updateTrendChart(data.recent_scans);
            }
        } catch (error) {
            console.error('Error fetching stats:', error);
        }
    }

    // Debounce function
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Initialize chart and fetch initial data
    if (document.getElementById('trendChart')) {
        initTrendChart();
        fetchStats();
        // Update stats every 30 seconds with debounce
        setInterval(debouncedFetchStats, 30000);
    }

    // Function to update trends and recent scans
    function updateDashboardData() {
        fetch('/calculate_stats')
            .then(response => response.json())
            .then(data => {
                // Update stats
                document.getElementById('totalScans').textContent = data.total_scans;
                document.getElementById('totalVulns').textContent = data.total_vulnerabilities;
                document.getElementById('successRate').textContent = data.success_rate + '%';
                document.getElementById('avgScanTime').textContent = data.average_scan_time + 's';

                // Update trends chart
                if (trendChart) {
                    const recentScans = data.recent_scans || [];
                    trendChart.data.labels = recentScans.map(scan => scan.timestamp);
                    trendChart.data.datasets[0].data = recentScans.map(scan => {
                        try {
                            return JSON.parse(scan.vulnerabilities).length;
                        } catch (e) {
                            return 0;
                        }
                    });
                    trendChart.update();
                }

                // Update recent scans table
                updateRecentScansTable();
            })
            .catch(error => console.error('Error updating dashboard:', error));
    }

    // Function to update recent scans table
    function updateRecentScansTable() {
        fetch('/recent_scans')
            .then(response => response.json())
            .then(data => {
                const tableBody = document.getElementById('recentScansTable');
                if (!tableBody) return;

                // Clear existing rows
                tableBody.innerHTML = '';

                // Add new rows
                data.scans.forEach(scan => {
                    const row = document.createElement('tr');
                    const vulnerabilities = JSON.parse(scan.vulnerabilities || '[]');
                    const vulnCount = vulnerabilities.length;
                    
                    row.innerHTML = `
                        <td>${formatDate(scan.created_at)}</td>
                        <td>${scan.target_url}</td>
                        <td>${scan.scan_duration ? scan.scan_duration.toFixed(2) + 's' : 'N/A'}</td>
                        <td>
                            <span class="badge ${vulnCount > 0 ? 'bg-danger' : 'bg-success'}">
                                ${vulnCount}
                            </span>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-info view-details" data-scan-id="${scan.id}">
                                View Details
                            </button>
                        </td>
                    `;
                    tableBody.appendChild(row);
                });

                // Add click handlers for view details buttons
                document.querySelectorAll('.view-details').forEach(button => {
                    button.addEventListener('click', () => showScanDetails(button.dataset.scanId));
                });
            })
            .catch(error => console.error('Error updating recent scans:', error));
    }

    // Function to format date for display
    function formatDateForDisplay(dateString) {
        if (!dateString) return 'N/A';
        try {
            const date = new Date(dateString);
            return date.toLocaleString();
        } catch (e) {
            console.error('Error formatting date:', e);
            return dateString;
        }
    }

    // Function to format vulnerabilities for display
    function formatVulnerabilities(vulnerabilities) {
        if (!vulnerabilities) return [];
        
        // If vulnerabilities is already an object/array, return as is
        if (typeof vulnerabilities === 'object') {
            return vulnerabilities;
        }
        
        // Try parsing if it's a string
        try {
            return JSON.parse(vulnerabilities);
        } catch (e) {
            console.error('Error parsing vulnerabilities:', e);
            return [];
        }
    }

    // Function to show scan details in modal
    function showScanDetails(scanId) {
        fetch(`/scan_details/${scanId}`)
            .then(response => response.json())
            .then(data => {
                try {
                    // Format the scan date
                    const scanDate = formatDateForDisplay(data.created_at);
                    document.getElementById('scanDetailsDate').textContent = scanDate;
                    
                    // Format and display vulnerabilities
                    const vulnerabilities = formatVulnerabilities(data.vulnerabilities);
                    
                    // Group vulnerabilities by type
                    const vulnsByType = {};
                    vulnerabilities.forEach(vuln => {
                        const type = vuln.type || 'Unknown';
                        if (!vulnsByType[type]) {
                            vulnsByType[type] = [];
                        }
                        vulnsByType[type].push(vuln);
                    });

                    // Sort vulnerability types and create HTML
                    const sortedTypes = Object.entries(vulnsByType).sort((a, b) => b[1].length - a[1].length);
                    
                    // Update modal content
                    const modalContent = document.getElementById('vulnerabilityDetails');
                    modalContent.innerHTML = sortedTypes.map(([type, vulns]) => `
                        <div class="vulnerability-type mb-4">
                            <h5 class="vulnerability-type-title">${type} (${vulns.length})</h5>
                            ${vulns.map(vuln => `
                                <div class="vulnerability-instance card mb-3">
                                    <div class="card-body">
                                        <div class="severity-badge ${vuln.severity || 'low'}">${vuln.severity || 'low'}</div>
                                        <p class="vuln-description mb-0">${vuln.description || 'No description available'}</p>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="detail-group mb-3">
                                                <h6 class="detail-title">Location</h6>
                                                <code class="d-block p-2 card rounded text-nowrap overflow-auto" style="white-space: nowrap; max-width: 100%;">${vuln.location || 'N/A'}</code>
                                            </div>
                                            ${vuln.method ? `
                                                <div class="detail-group mb-3">
                                                    <h6 class="detail-title">Method</h6>
                                                    <code class="d-block p-2 card rounded">${vuln.method}</code>
                                                </div>
                                            ` : ''}
                                        </div>
                                        <div class="col-md-6">
                                            ${vuln.parameter ? `
                                                <div class="detail-group mb-3">
                                                    <h6 class="detail-title">Parameter</h6>
                                                    <code class="d-block p-2 card rounded">${vuln.parameter}</code>
                                                </div>
                                            ` : ''}
                                            ${vuln.payload ? `
                                                <div class="detail-group mb-3">
                                                    <h6 class="detail-title">Payload</h6>
                                                    <code class="d-block p-2 card rounded">${vuln.payload}</code>
                                                </div>
                                            ` : ''}
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    `).join('');

                    // Show the modal
                    const scanDetailsModal = new bootstrap.Modal(document.getElementById('scanDetailsModal'));
                    scanDetailsModal.show();
                } catch (error) {
                    console.error('Error processing scan details:', error);
                }
            })
            .catch(error => {
                console.error('Error loading scan details:', error);
            });
    }

    // Helper function to format date
    function formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString();
    }

    // WebSocket connection for real-time updates
    let socket;

    function connectWebSocket() {
        // Check if WebSocket is already connected
        if (socket && socket.readyState === WebSocket.OPEN) return;

        // Create WebSocket connection
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        socket = new WebSocket(wsUrl);

        socket.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.type === 'scan_complete') {
                // Update dashboard data when scan completes
                updateDashboardData();
            }
        };

        socket.onclose = function() {
            // Reconnect after 5 seconds if connection is closed
            setTimeout(connectWebSocket, 5000);
        };
    }

    // Initialize real-time updates
    document.addEventListener('DOMContentLoaded', function() {
        // Initial load
        updateDashboardData();
        
        // Connect WebSocket for real-time updates
        connectWebSocket();
        
        // Fallback: Regular polling every 30 seconds
        setInterval(updateDashboardData, 30000);
    });

    // Function to format ISO timestamp to HH:mm
    function formatTimeForChart(isoString) {
        const date = new Date(isoString);
        return date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit',
            hour12: false 
        });
    }

    // Function to format ISO timestamp to readable date
    function formatDateForDisplay(isoString) {
        const date = new Date(isoString);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });
    }

    // Function to group data by hour
    function groupDataByHour(data) {
        const hourlyData = {};
        
        data.forEach(item => {
            const date = new Date(item.created_at);
            const hour = date.toLocaleTimeString('en-US', { 
                hour: '2-digit', 
                hour12: false 
            });
            
            if (!hourlyData[hour]) {
                hourlyData[hour] = {
                    count: 0,
                    vulnerabilities: 0
                };
            }
            
            hourlyData[hour].count++;
            try {
                const vulns = JSON.parse(item.vulnerabilities || '[]');
                hourlyData[hour].vulnerabilities += vulns.length;
            } catch (e) {
                console.error('Error parsing vulnerabilities:', e);
            }
        });
        
        return hourlyData;
    }

    // Function to update vulnerability trends chart
    function updateVulnerabilityTrends() {
        fetch('/dashboard_data')
            .then(response => response.json())
            .then(data => {
                if (!data.scans || !data.scans.length) return;

                // Sort scans by timestamp
                const sortedScans = data.scans.sort((a, b) => 
                    new Date(a.created_at) - new Date(b.created_at)
                );

                // Get last 24 entries or all if less
                const recentScans = sortedScans.slice(-24);

                // Process data for chart
                const labels = recentScans.map(scan => formatTimeForChart(scan.created_at));
                const vulnCounts = recentScans.map(scan => {
                    try {
                        return JSON.parse(scan.vulnerabilities || '[]').length;
                    } catch (e) {
                        return 0;
                    }
                });

                // Update chart
                if (trendChart) {
                    trendChart.data.labels = labels;
                    trendChart.data.datasets[0].data = vulnCounts;
                    trendChart.update();
                } else {
                    // Initialize chart if it doesn't exist
                    const ctx = document.getElementById('trendChart').getContext('2d');
                    trendChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Vulnerabilities Found',
                                data: vulnCounts,
                                borderColor: '#4CAF50',
                                backgroundColor: 'rgba(76, 175, 80, 0.1)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.4
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    display: true,
                                    labels: {
                                        color: '#fff'
                                    }
                                },
                                tooltip: {
                                    mode: 'index',
                                    intersect: false,
                                    callbacks: {
                                        title: function(tooltipItems) {
                                            const index = tooltipItems[0].dataIndex;
                                            return formatDateForDisplay(recentScans[index].created_at);
                                        }
                                    }
                                }
                            },
                            scales: {
                                x: {
                                    grid: {
                                        color: 'rgba(255, 255, 255, 0.1)'
                                    },
                                    ticks: {
                                        color: '#fff',
                                        maxRotation: 45,
                                        minRotation: 45
                                    }
                                },
                                y: {
                                    beginAtZero: true,
                                    grid: {
                                        color: 'rgba(255, 255, 255, 0.1)'
                                    },
                                    ticks: {
                                        color: '#fff',
                                        stepSize: 1
                                    }
                                }
                            }
                        }
                    });
                }
            })
            .catch(error => console.error('Error updating vulnerability trends:', error));
    }

  

    // Add CSS styles for recent scans
    const recentScansStyles = `
        .scan-list {
            max-height: 400px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--primary-color) var(--background);
        }
        .scan-list::-webkit-scrollbar {
            width: 6px;
        }
        .scan-list::-webkit-scrollbar-track {
            background: var(--background);
        }
        .scan-list::-webkit-scrollbar-thumb {
            background-color: var(--primary-color);
            border-radius: 3px;
        }
        .scan-item {
            background: var(--card-background);;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            border-radius: 12px;
            overflow: hidden;
        }
        .scan-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
        }
        .scan-content {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .scan-header {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .url-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .url-container i {
            font-size: 1rem;
        }
        .url-container h6 {
            font-weight: 600;
            color: var(--text-primary);
            margin: 0;
            flex: 1;
            max-width: calc(100% - 2rem);
        }
        .scan-meta {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .timestamp {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .scan-stats {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .stats-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .badge {
            padding: 0.5rem 0.75rem;
            font-size: 0.85rem;
            font-weight: 500;
            border-radius: 20px;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            white-space: nowrap;
        }
        .badge i {
            font-size: 0.9rem;
        }
        .badge-danger {
            background: linear-gradient(135deg, #ff4757, #ff6b81);
            color: white;
        }
        .badge-success {
            background: linear-gradient(135deg, #2ed573, #7bed9f);
            color: white;
        }
        .badge-info {
            background: linear-gradient(135deg, #1e90ff, #70a1ff);
            color: white;
        }
        .badge-warning {
            background: linear-gradient(135deg, #ffa502, #ffb88c);
            color: white;
        }
        @media (max-width: 576px) {
            .scan-header {
                gap: 0.75rem;
            }
            .scan-meta {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
            .stats-badges {
                flex-direction: column;
                width: 100%;
            }
            .badge {
                width: 100%;
                justify-content: center;
            }
        }
    `;

    // Add the styles to the document
    const styleSheet = document.createElement("style");
    styleSheet.textContent = recentScansStyles;
    document.head.appendChild(styleSheet);

    // Call updateRecentScans initially and set up interval
    document.addEventListener('DOMContentLoaded', function() {
        updateRecentScans();
        // Update recent scans every 30 seconds
        setInterval(updateRecentScans, 30000);
    });

    // Add CSS styles for the new elements
    const style = document.createElement('style');
    style.textContent = `
        .vulnerability-item {
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 8px;
            background: var(--card-background);;
            border: 1px solid var(--border);
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .vuln-description {
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }

        .vuln-details {
            background: rgba(0, 0, 0, 0.2);
            padding: 1rem;
            border-radius: 6px;
            margin-top: 1rem;
        }

        .detail-row {
            margin-bottom: 0.5rem;
        }

        .detail-row:last-child {
            margin-bottom: 0;
        }

        .detail-row code {
            background: rgba(0, 0, 0, 0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            color: var(--primary-color);
        }

        .evidence-code {
            background: rgba(0, 0, 0, 0.3);
            padding: 0.5rem;
            border-radius: 4px;
            margin: 0.5rem 0;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .technical-code {
            background: rgba(0, 0, 0, 0.3);
            padding: 1rem;
            border-radius: 4px;
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
            color: var(--text-secondary);
        }

        .severity {
            padding: 0.25rem 0.75rem;
            border-radius: 100px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity.critical {
            background: rgba(255, 71, 87, 0.2);
            color: var(--critical-color);
        }

        .severity.high {
            background: rgba(255, 165, 2, 0.2);
            color: var(--high-color);
        }

        .severity.medium {
            background: rgba(0, 210, 211, 0.2);
            color: var(--medium-color);
        }

        .severity.low {
            background: rgba(0, 255, 157, 0.2);
            color: var(--low-color);
        }
    `;

    document.head.appendChild(style);
}); 