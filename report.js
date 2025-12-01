// Get URL parameters
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    if (!targetUrl) {
        showError('No URL provided');
    } else {
        loadReport(targetUrl);
    }
});

async function loadReport(url) {
    try {
        // Send message to background script to get detailed report
        const response = await chrome.runtime.sendMessage({
            action: 'getDetailedReport',
            url: url
        });
        
        if (response.error) {
            showError(response.error);
        } else {
            displayReport(response);
        }
    } catch (error) {
        showError(error.message);
    }
}

function displayReport(data) {
    const loader = document.getElementById('loader');
    const content = document.getElementById('content');
    
    if (!loader || !content) return;
    
    loader.style.display = 'none';
    content.style.display = 'block';
    
    // Display basic info
    const urlElement = document.getElementById('url');
    const detectionRateElement = document.getElementById('detectionRate');
    const scanDateElement = document.getElementById('scanDate');
    const vtLinkElement = document.getElementById('vtLink');
    const detectionCard = document.getElementById('detectionCard');
    const statusBadge = document.getElementById('statusBadge');
    
    if (urlElement) urlElement.textContent = data.url || targetUrl;
    if (detectionRateElement) detectionRateElement.textContent = `${data.positives}/${data.total}`;
    if (scanDateElement) scanDateElement.textContent = formatDate(data.scan_date);
    if (vtLinkElement) vtLinkElement.href = data.permalink || '#';
    
    // Set detection card style and badge
    if (detectionCard && statusBadge) {
        if (data.positives === 0) {
            detectionCard.classList.add('safe');
            statusBadge.innerHTML = '<span class="status-badge safe">✓ Secure</span>';
        } else if (data.positives > 0 && data.positives <= 3) {
            detectionCard.classList.add('neutral');
            statusBadge.innerHTML = '<span class="status-badge warning">⚠ Suspicious</span>';
        } else {
            detectionCard.classList.add('danger');
            statusBadge.innerHTML = '<span class="status-badge danger">⚠ Threat Detected</span>';
        }
    }
    
    // Display detections
    if (data.scans && Object.keys(data.scans).length > 0) {
        const detections = [];
        const cleanEngines = [];
        
        Object.keys(data.scans).forEach(engine => {
            const result = data.scans[engine];
            if (result.detected) {
                detections.push({ engine, result: result.result || 'Malicious' });
            } else {
                cleanEngines.push(engine);
            }
        });
        
        // Show malicious detections
        if (detections.length > 0) {
            const threatSection = document.getElementById('threatSection');
            const detectionsDiv = document.getElementById('detections');
            
            if (threatSection && detectionsDiv) {
                threatSection.style.display = 'block';
                detectionsDiv.innerHTML = detections.map(d => `
                    <div class="vendor-item threat">
                        <span class="vendor-name">${escapeHtml(d.engine)}</span>
                        <span class="vendor-result threat">${escapeHtml(d.result)}</span>
                    </div>
                `).join('');
            }
        }
        
        // Show clean results
        if (cleanEngines.length > 0) {
            const cleanSection = document.getElementById('cleanSection');
            const cleanDiv = document.getElementById('cleanEngines');
            
            if (cleanSection && cleanDiv) {
                cleanSection.style.display = 'block';
                cleanDiv.innerHTML = cleanEngines.map(engine => `
                    <div class="vendor-item safe">
                        <span class="vendor-name">${escapeHtml(engine)}</span>
                        <span class="vendor-result safe">Clean</span>
                    </div>
                `).join('');
            }
        }
    }
}

function showError(message) {
    const loader = document.getElementById('loader');
    const error = document.getElementById('error');
    const errorMessage = document.getElementById('errorMessage');
    
    if (loader) loader.style.display = 'none';
    if (error) error.style.display = 'block';
    if (errorMessage) errorMessage.textContent = message;
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (e) {
        return dateString;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}