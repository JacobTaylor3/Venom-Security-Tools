// code for the tabs section of our scan-ui page

// DOM Elements
const themeToggle = document.getElementById('themeToggle');
const scanButton = document.getElementById('scanButton');
const discoverButton = document.getElementById('discoverButton');
const stressButton = document.getElementById('stressButton');
const tabButtons = document.querySelectorAll('.tab-button');
const toolSections = document.querySelectorAll('.tool-section');

// Track history of scans for the "History" tab
let scanHistory = [];

// Theme Toggle
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-mode');
});

// Tab Switching Logic
tabButtons.forEach(button => {
    button.addEventListener('click', () => {
        tabButtons.forEach(btn => btn.classList.remove('active'));
        toolSections.forEach(section => section.classList.remove('active'));
        
        button.classList.add('active');
        document.getElementById(button.dataset.tab).classList.add('active');
    });
});

// Port Scanner Logic
scanButton.addEventListener('click', () => {
    const hostname = document.getElementById('hostname').value;
    const startPort = parseInt(document.getElementById('startPort').value, 10);
    const endPort = parseInt(document.getElementById('endPort').value, 10);
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const progressBar = document.querySelector('.progress-bar');
    const progress = document.getElementById('progress');

    if (!hostname || isNaN(startPort) || isNaN(endPort) || startPort > endPort) {
        alert("Please enter a valid hostname/IP and a port range.");
        return;
    }

    loading.style.display = 'block';
    results.classList.add('hidden');
    progressBar.classList.remove('hidden');
    progress.style.width = '0';

    // Simulate scanning process
    let currentPort = startPort;
    results.innerHTML = `<h3>Results for ${hostname}:</h3><ul>`;
    
    let interval = setInterval(() => {
        if (currentPort > endPort) {
            clearInterval(interval);
            loading.style.display = 'none';
            results.classList.remove('hidden');
            progressBar.classList.add('hidden');
            results.innerHTML += '</ul>';
            scanHistory.push(`Scanned ${hostname} from port ${startPort} to ${endPort}`);
            updateHistory();
            return;
        }

        const portStatus = currentPort % 2 === 0 ? 'Open' : 'Closed';
        const statusClass = portStatus === 'Open' ? 'open' : 'closed';
        
        results.innerHTML += `<li><strong>Port ${currentPort}:</strong> <span class="${statusClass}">${portStatus}</span></li>`;
        progress.style.width = ((currentPort - startPort) / (endPort - startPort) * 100) + '%';

        currentPort += 1;
    }, 100);
});

// Network Discovery Logic
discoverButton.addEventListener('click', () => {
    const subnet = document.getElementById('subnet').value;
    const discoveryLoading = document.getElementById('discoveryLoading');
    const discoveryResults = document.getElementById('discoveryResults');

    if (!subnet) {
        alert("Please enter a valid subnet (e.g., 192.168.1.0/24).");
        return;
    }

    discoveryLoading.style.display = 'block';
    discoveryResults.classList.add('hidden');
    discoveryResults.innerHTML = '';

    // Simulate network discovery
    setTimeout(() => {
        discoveryLoading.style.display = 'none';
        discoveryResults.classList.remove('hidden');
        
        // Simulated list of discovered devices
        const devices = [
            { ip: '192.168.1.10', name: 'Device 1' },
            { ip: '192.168.1.15', name: 'Device 2' },
            { ip: '192.168.1.20', name: 'Device 3' }
        ];
        
        discoveryResults.innerHTML = `<h3>Devices found in ${subnet}:</h3><ul>`;
        devices.forEach(device => {
            discoveryResults.innerHTML += `<li><strong>${device.name}</strong> - ${device.ip}</li>`;
        });
        discoveryResults.innerHTML += '</ul>';

        scanHistory.push(`Discovered devices in subnet ${subnet}`);
        updateHistory();
    }, 2000);
});

// Network Stress Test Logic
stressButton.addEventListener('click', () => {
    const targetIP = document.getElementById('targetIP').value;
    const packetSize = parseInt(document.getElementById('packetSize').value, 10);
    const stressLoading = document.getElementById('stressLoading');
    const stressResults = document.getElementById('stressResults');

    if (!targetIP || isNaN(packetSize) || packetSize < 32 || packetSize > 65507) {
        alert("Please enter a valid target IP and packet size (32-65507 bytes).");
        return;
    }

    stressLoading.style.display = 'block';
    stressResults.classList.add('hidden');
    stressResults.innerHTML = '';

    // Simulate stress test
    setTimeout(() => {
        stressLoading.style.display = 'none';
        stressResults.classList.remove('hidden');
        
        stressResults.innerHTML = `<p>Stress Test on ${targetIP} completed. Target responded successfully with packet size of ${packetSize} bytes.</p>`;

        scanHistory.push(`Stress test on ${targetIP} with ${packetSize} byte packets`);
        updateHistory();
    }, 3000);
});

// Update Scan History
function updateHistory() {
    const historyContent = document.getElementById('historyContent');
    if (scanHistory.length === 0) {
        historyContent.innerHTML = "<p>No history available yet.</p>";
    } else {
        historyContent.innerHTML = "<ul>";
        scanHistory.forEach(entry => {
            historyContent.innerHTML += `<li>${entry}</li>`;
        });
        historyContent.innerHTML += "</ul>";
    }
}


