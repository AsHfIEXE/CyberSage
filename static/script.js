document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scan-form');
    const submitButton = document.getElementById('submitScanButton');
    const scanButtonText = document.getElementById('scanButtonText'); // Assuming you have a span for text
    const scanButtonSpinner = document.getElementById('scanButtonSpinner'); // Assuming you have an SVG spinner

    const progressSection = document.getElementById('progress-section');
    const progressBar = document.getElementById('progress-bar');
    const progressBarText = document.getElementById('progress-bar-text');
    const statusTextContainer = document.getElementById('status-text-container');
    const statusTextList = document.getElementById('status-text'); // Changed to ul
    const scanIdDisplay = document.getElementById('scan-id-display'); // For showing Scan ID
    const errorMessageDiv = document.getElementById('error-message');

    let currentScanId = null;
    let sseConnection = null;
    let scanIsRunning = false;

    function updateButtonState(text, showSpinner, isDisabled) {
        if (scanButtonText) scanButtonText.textContent = text;
        if (scanButtonSpinner) scanButtonSpinner.style.display = showSpinner ? 'inline' : 'none';
        if (submitButton) submitButton.disabled = isDisabled;
    }

    if (scanForm) {
        scanForm.addEventListener('submit', function(event) {
            event.preventDefault();
            if (scanIsRunning) return; // Prevent starting multiple scans

            const target = document.getElementById('target').value;
            if (!target.trim()) { showError("Target URL or Domain cannot be empty."); return; }
            hideError();

            scanIsRunning = true;
            updateButtonState("Initiating Scan", true, true);
            
            if(progressSection) progressSection.classList.remove('hidden');
            if(progressBar) progressBar.style.width = '0%';
            if(progressBarText) progressBarText.textContent = '0%';
            if(statusTextList) statusTextList.innerHTML = ''; // Clear previous logs
            if(scanIdDisplay) scanIdDisplay.textContent = '';

            addStatusLog('Sending scan request...', 'INFO', 'System');

            fetch('/start_scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({ 'target': target })
            })
            .then(response => {
                if (!response.ok) { // Check for non-2xx HTTP responses
                    return response.json().then(errData => { throw new Error(errData.error || `Server error: ${response.status}`) });
                }
                return response.json();
            })
            .then(data => {
                if (data.success && data.scan_id) {
                    currentScanId = data.scan_id;
                    if(scanIdDisplay) scanIdDisplay.textContent = `Scan ID: ${currentScanId}`;
                    addStatusLog(`Scan initiated. Waiting for progress...`, 'SUCCESS', 'Core');
                    updateButtonState("Scan Running...", true, true);
                    connectSSE(currentScanId);
                } else {
                    showError(data.error || 'Failed to start scan. Unknown server response.');
                    resetFormState();
                }
            })
            .catch(error => {
                console.error('Error starting scan:', error);
                showError(error.message || 'Network error or server unavailable. Could not start scan.');
                resetFormState();
            });
        });
    }

    function addStatusLog(message, status = "INFO", toolName = "System") {
        if (!statusTextList) return;
        const listItem = document.createElement('li');
        const time = new Date().toLocaleTimeString();
        
        let statusClass = 'text-gray-300'; // Default
        let prefixIcon = '';

        switch(status.toUpperCase()) {
            case "SUCCESS": statusClass = 'text-green-400'; prefixIcon = '✅ '; break;
            case "ERROR": statusClass = 'text-red-400'; prefixIcon = '❌ '; break;
            case "WARNING": statusClass = 'text-yellow-400'; prefixIcon = '⚠️ '; break;
            case "INFO": statusClass = 'text-blue-400'; prefixIcon = 'ℹ️ '; break;
            case "STAGE_START": statusClass = 'text-indigo-400'; prefixIcon = '🚀 '; break;
            case "STAGE_END": statusClass = 'text-indigo-400'; prefixIcon = '🏁 '; break; // Changed from checkmark to distinguish from general success
        }
        
        listItem.className = `${statusClass} py-1 border-b border-gray-600 last:border-b-0`;
        listItem.innerHTML = `<span class="font-mono text-xs text-gray-500">${time}</span> ${prefixIcon}<strong class="font-medium">${toolName}:</strong> ${message}`;
        statusTextList.appendChild(listItem);
        if (statusTextContainer) statusTextContainer.scrollTop = statusTextContainer.scrollHeight;
    }

    function connectSSE(scanId) {
        if (sseConnection && sseConnection.readyState !== EventSource.CLOSED) {
            sseConnection.close();
        }
        sseConnection = new EventSource(`/progress/${scanId}`);

        sseConnection.onopen = function() {
            addStatusLog("Connected to progress stream.", "INFO", "SSE Connection");
        };

        sseConnection.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);

                if (data.message === "SSE_STREAM_END") {
                    sseConnection.close();
                    addStatusLog("Progress stream ended by server.", "INFO_FINAL", "SSE Connection");
                    handleScanCompletion(currentScanId, "Scan completed or stream ended.");
                    return;
                }

                addStatusLog(data.message, data.status, data.tool);

                if (progressBar && data.percent_complete !== undefined) {
                    progressBar.style.width = data.percent_complete + '%';
                    if(progressBarText) progressBarText.textContent = data.percent_complete + '%';
                }

                // Check for final scan status messages from the Core tool
                if (data.tool === "Core" && 
                    (data.message.toLowerCase().includes("scan completed") || 
                     data.message.toLowerCase().includes("scan failed") ||
                     data.message.toLowerCase().includes("scan ended with status") || // Catches nuanced statuses
                     data.status === "INFO_FINAL" // My custom final status
                    )) {
                    handleScanCompletion(scanId, data.message);
                    // Don't close SSE here immediately; wait for SSE_STREAM_END for graceful server-side cleanup.
                }
            } catch (e) {
                console.error("Error parsing SSE data:", e, "Data:", event.data);
                addStatusLog("Received malformed progress update.", "ERROR", "SSE Parser");
            }
        };

        sseConnection.onerror = function(error) {
            console.error("SSE Connection Error:", error);
            addStatusLog("SSE connection error. Updates may have stopped. Check network/server.", "ERROR", "SSE Connection");
            // Browser might attempt to reconnect automatically.
            // If it's a final error, the server should close the connection.
            // If scan was running, it might still complete. UI might need a manual refresh then.
            // Consider adding a button to manually check status or reload if SSE fails terminally.
            updateButtonState("Scan Interrupted (Retry/View Results)", false, false); // Allow user to retry or view results
            scanIsRunning = false; // Allow form resubmission
        };
    }
    
    function handleScanCompletion(scanId, finalMessage) {
        addStatusLog(finalMessage, "INFO_FINAL", "Core");
        updateButtonState("View Results", false, false); // Change button to "View Results"
        submitButton.onclick = function() { // Change button action
            window.location.href = `/results/${scanId}`;
        };
        scanIsRunning = false; // Allow new scan to be started
        // The SSE_STREAM_END event will actually close the SSE connection.
    }

    function resetFormState() {
        scanIsRunning = false;
        updateButtonState("Start Scan", false, false);
        if (submitButton) submitButton.onclick = null; // Reset to default form submission
        currentScanId = null;
        if (sseConnection && sseConnection.readyState !== EventSource.CLOSED) {
            sseConnection.close();
        }
    }

    function showError(message) { 
        if (errorMessageDiv) { 
            errorMessageDiv.textContent = message; 
            errorMessageDiv.classList.remove('hidden'); 
        } 
    }
    function hideError() { 
        if (errorMessageDiv) { 
            errorMessageDiv.classList.add('hidden'); 
        } 
    }
});