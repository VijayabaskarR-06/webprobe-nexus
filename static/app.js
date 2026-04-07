document.addEventListener('DOMContentLoaded', () => {
    const inputPanel = document.getElementById('input-panel');
    const scanningPanel = document.getElementById('scanning-panel');
    const resultsPanel = document.getElementById('results-panel');
    const form = document.getElementById('scan-form');
    const resetBtn = document.getElementById('reset-btn');

    const showPanel = (panelToShow) => {
        const activePanels = [inputPanel, scanningPanel, resultsPanel].filter(p => p.style.display !== 'none');
        
        // Fade out active
        activePanels.forEach(p => {
            p.classList.add('fade-out');
            p.classList.remove('fade-in');
        });

        setTimeout(() => {
            activePanels.forEach(p => p.style.display = 'none');
            
            // Show new
            panelToShow.style.display = 'block';
            panelToShow.classList.remove('fade-out');
            panelToShow.classList.add('fade-in');
        }, 500);
    };

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const url = document.getElementById('target-url').value;
        const depth = parseInt(document.getElementById('depth').value);
        const skipDirs = document.getElementById('skip-dirs').checked;

        showPanel(scanningPanel);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, depth, threads: 10, skip_dirs: skipDirs })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.detail || 'Scan request failed to process.');
            }

            const data = await response.json();
            renderResults(data);
            showPanel(resultsPanel);

        } catch (error) {
            alert(`Execution Error: ${error.message}`);
            showPanel(inputPanel);
        }
    });

    const renderResults = (data) => {
        const totals = data.total_vulnerabilities || { sqli: 0, xss: 0, missing_headers: 0, open_directories: 0 };
        
        // Rolling counter animation
        animateValue("sqli-count", 0, totals.sqli, 1500);
        animateValue("xss-count", 0, totals.xss, 1500);
        animateValue("header-count", 0, totals.missing_headers, 1500);
        animateValue("dir-count", 0, totals.open_directories, 1500);

        const logContainer = document.getElementById('log-container');
        logContainer.innerHTML = '';
        
        const vulnerabilities = data.vulnerabilities || [];

        if (vulnerabilities.length > 0) {
            // Apply stagger effect
            vulnerabilities.forEach((vuln, index) => {
                const div = document.createElement('div');
                div.className = `log-item ${getSeverityClass(vuln.type)}`;
                div.style.opacity = '0';
                div.style.transform = 'translateY(10px)';
                div.style.transition = 'all 0.5s ease';
                div.innerHTML = `<strong>[${(vuln.type || 'UNKNOWN').toUpperCase()}]</strong> <br/> ${vuln.details || vuln.description || vuln.url || 'Details empty'}`;
                
                logContainer.appendChild(div);

                setTimeout(() => {
                    div.style.opacity = '1';
                    div.style.transform = 'translateY(0)';
                }, 300 + (index * 100)); // Stagger array rendering
            });
        } else {
            const div = document.createElement('div');
            div.className = 'log-item info';
            div.innerHTML = '<strong>[SECURE]</strong> No severe vulnerabilities detected on the surface layer vectors.';
            logContainer.appendChild(div);
        }
    };

    function getSeverityClass(type) {
        if (!type) return 'info';
        const t = type.toLowerCase();
        if (t.includes('sqli') || t.includes('xss') || t.includes('vuln')) return 'critical';
        if (t.includes('header') || t.includes('missing')) return 'warning';
        return 'info';
    }

    function animateValue(id, start, end, duration) {
        if (!end || end === 0) { document.getElementById(id).innerHTML = "0"; return; }
        const obj = document.getElementById(id);
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            } else {
                obj.innerHTML = end;
            }
        };
        window.requestAnimationFrame(step);
    }

    resetBtn.addEventListener('click', () => {
        showPanel(inputPanel);
        form.reset();
    });
});
