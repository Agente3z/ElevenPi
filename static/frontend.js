const socket = io();
let interfaces = {};
let selectedInterface = null;
let selectedAP = null;
let selectedClient = null;

function updateInterfaces() {
    socket.emit('list_interfaces');
}

socket.on('interfaces_data', data => {
    interfaces = {};
    data.interfaces.forEach(iface => {
        interfaces[iface.iface] = iface.mode;
    });

    const interfacesList = document.getElementById('interfaces-list');
    interfacesList.innerHTML = '';

    data.interfaces.forEach(iface => {
        const item = document.createElement('div');
        item.className = 'interface-item';
        item.onclick = () => selectInterface(iface.iface);
        item.innerHTML = `
            <p>${iface.iface}</p>
            <div id="details-${iface.iface}" class="interface-details" style="display: none;">
                <label>Mode: ${iface.mode}</label>
                <button onclick="changeInterfaceMode('${iface.iface}', 'monitor')">Switch to Monitor</button>
                <button onclick="changeInterfaceMode('${iface.iface}', 'managed')">Switch to Managed</button>
            </div>
        `;
        interfacesList.appendChild(item);
    });

    if (selectedInterface) {
        selectInterface(selectedInterface);
    }
});

function selectInterface(name) {
    selectedInterface = name;
    document.querySelectorAll('.interface-details').forEach(details => {
        details.style.display = 'none';
    });
    document.getElementById(`details-${name}`).style.display = 'block';
}

function changeInterfaceMode(name, mode) {
    socket.emit('iface_set_mode', { iface: name, mode });
}

socket.on('iface_set_mode_data', data => {
    updateInterfaces();
});

function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(sectionId).classList.add('active');
}

function manageServices(option) {
    document.querySelectorAll('#services-control button').forEach(button => {
        button.disabled = true;
    });
    socket.emit('manage_services', { option });
}

socket.on('manage_services_data', data => {
    if (data.option === 'start') {
        document.getElementById('start-services').disabled = true;
        document.getElementById('stop-services').disabled = false;
    } else if (data.option === 'stop') {
        document.getElementById('start-services').disabled = false;
        document.getElementById('stop-services').disabled = true;
    }
});

function startAPScan() {
    document.getElementById('ap-list').innerHTML = '';
    const iface = selectedInterface;
    if (iface) {
        socket.emit('scan_ap', { iface });
        document.getElementById('start-ap-scan-btn').disabled = true;
        document.getElementById('stop-ap-scan-btn').disabled = false;
        toggleSectionsAvailability(false, ['ap-scan']);
    } else {
        alert('Please select an interface.');
    }
}

function stopAPScan() {
    socket.emit('stop_scan_ap');
    document.getElementById('start-ap-scan-btn').disabled = false;
    document.getElementById('stop-ap-scan-btn').disabled = true;
    toggleSectionsAvailability(true);
}

function toggleSectionsAvailability(enable, exceptions = []) {
    document.querySelectorAll('#sidebar .menu-item').forEach(menuItem => {
        const section = menuItem.getAttribute('data-section');
        if (enable || exceptions.includes(section)) {
            menuItem.onclick = () => showSection(section);
            menuItem.style.pointerEvents = 'auto';
            menuItem.style.opacity = '1';
        } else {
            menuItem.onclick = null;
            menuItem.style.pointerEvents = 'none';
            menuItem.style.opacity = '0.5';
        }
    });
}

socket.on('new_ap', data => {
    const apList = document.getElementById('ap-list');
    const apItem = document.createElement('div');
    apItem.className = 'ap-item';
    apItem.innerHTML = `
        <p>SSID: ${data.ssid}</p>
        <p>BSSID: ${data.bssid}</p>
        <p>Channel: ${data.channel}</p>
    `;
    apItem.onclick = () => selectAP(data);
    apList.appendChild(apItem);
});

function selectAP(ap) {
    selectedAP = ap;
    document.querySelectorAll('.ap-item').forEach(item => {
        item.classList.remove('selected');
    });
    const apItems = document.querySelectorAll('.ap-item');
    apItems.forEach(item => {
        if (item.innerHTML.includes(ap.bssid)) {
            item.classList.add('selected');
        }
    });
}

function startSniffing() {
    const iface = selectedInterface;
    const ap = selectedAP;
    if (iface && ap) {
        socket.emit('start_sniffing', { iface, ssid: ap.ssid, bssid: ap.bssid, channel: ap.channel });
        document.getElementById('sniffing-status').innerText = 'Sniffing started...';
        document.getElementById('start-sniff-btn').disabled = true;
        document.getElementById('stop-sniff-btn').disabled = false;
        document.getElementById('start-sharing-btn').disabled = true;
        toggleSectionsAvailability(false, ['clients', 'sniffing']);
    } else {
        alert('Please select an interface and an AP.');
    }
}

function stopSniffing() {
    socket.emit('stop_sniffing');
    document.getElementById('sniffing-status').innerText = 'Sniffing stopped.';
    document.getElementById('start-sniff-btn').disabled = false;
    document.getElementById('stop-sniff-btn').disabled = true;
    document.getElementById('start-sharing-btn').disabled = false;
    if (document.getElementById('stop-client-scan-btn').disabled) {
        toggleSectionsAvailability(true);
    } else {
        toggleSectionsAvailability(false, ['clients', 'sniffing']);
    }
}

socket.on('sniffing_data', data => {
    if (data.message === "Hash found") {
        stopSniffing();
        document.getElementById('sniffing-status').innerText = 'Hash found';
        alert('Hash found');
    }
});

function startClientScan() {
    document.getElementById('client-list').innerHTML = '<div class="client-item" data-client="ff:ff:ff:ff:ff:ff" onclick="selectClient(\'ff:ff:ff:ff:ff:ff\')">Broadcast</div>';
    const iface = selectedInterface;
    const ap = selectedAP;
    if (iface && ap) {
        socket.emit('sniff_clients', { iface, ssid: ap.ssid, bssid: ap.bssid, channel: ap.channel });
        document.getElementById('start-client-scan-btn').disabled = true;
        document.getElementById('stop-client-scan-btn').disabled = false;
        toggleSectionsAvailability(false, ['clients', 'sniffing']);
    } else {
        alert('Please select an interface and an AP.');
    }
}

function stopClientScan() {
    socket.emit('stop_sniff_clients');
    document.getElementById('start-client-scan-btn').disabled = false;
    document.getElementById('stop-client-scan-btn').disabled = true;
    if (document.getElementById('stop-sniff-btn').disabled) {
        toggleSectionsAvailability(true);
    } else {
        toggleSectionsAvailability(false, ['clients', 'sniffing']);
    }
}

socket.on('new_client', data => {
    const clientList = document.getElementById('client-list');
    const clientItem = document.createElement('div');
    clientItem.className = 'client-item';
    clientItem.innerHTML = data.client;
    clientItem.setAttribute('data-client', data.client);
    clientItem.onclick = () => selectClient(data.client);
    clientList.appendChild(clientItem);
});

function selectClient(client) {
    selectedClient = client;
    document.querySelectorAll('.client-item').forEach(item => {
        item.classList.remove('selected');
    });
    document.querySelector(`.client-item[data-client="${client}"]`).classList.add('selected');
}

function startDeauth() {
    const iface = selectedInterface;
    const ap = selectedAP;
    const client = selectedClient;
    if (iface && ap && client) {
        socket.emit('deauth', { iface, ssid: ap.ssid, bssid: ap.bssid, channel: ap.channel, client });
    } else {
        alert('Please select an interface, an AP and a client.');
    }
}

function showConfirmationPopup() {
    const popup = document.getElementById('confirmation-popup');
    const overlay = document.getElementById('overlay');
    popup.style.display = 'block';
    overlay.style.display = 'block';
}

function hideConfirmationPopup() {
    const popup = document.getElementById('confirmation-popup');
    const overlay = document.getElementById('overlay');
    popup.style.display = 'none';
    overlay.style.display = 'none';
}

function confirmAction(action) {
    if (action === 'shutdown' || action === 'reboot') {
        socket.emit(action);
        hideConfirmationPopup();
    }
}

function startPortal() {
    document.getElementById('portal-logs').value = '';
    const iface = selectedInterface;
    const ap = selectedAP;
    if (iface && ap && interfaces[iface] === 'managed') {
        socket.emit('start_captive_portal', { iface, ssid: ap.ssid, bssid: ap.bssid, channel: ap.channel });
        document.getElementById('start-portal-btn').disabled = true;
        document.getElementById('stop-portal-btn').disabled = false;
        toggleSectionsAvailability(false, ['portal']);
    } else if (interfaces[iface] === 'monitor') {
        alert('Interface must be in managed mode to start the captive portal.');
    } else {
        alert('Please select an interface and an AP.');
    }
}

function stopPortal() {
    socket.emit('stop_captive_portal');
    socket.emit('iface_set_mode', { iface: selectedInterface, mode: "managed"});
    document.getElementById('stop-portal-btn').disabled = true;
}

socket.on('captive_portal_data', data => {
    const portalLogs = document.getElementById('portal-logs');
    portalLogs.value += data.message + '\n';
    portalLogs.scrollTop = portalLogs.scrollHeight;
    if (data.message === 'Key found') {
        stopPortal();
    } else if (data.message === 'Captive portal stopped') {
        document.getElementById('start-portal-btn').disabled = false;
        toggleSectionsAvailability(true);
    }
});

socket.on('journalctl_output', data => {
    const logsContainer = document.getElementById('logs-container');
    logsContainer.value += data.message + '\n';
    logsContainer.scrollTop = logsContainer.scrollHeight;
});

function showLogsPopup() {
    const popup = document.getElementById('logs-popup');
    const overlay = document.getElementById('overlay');
    popup.style.display = 'block';
    overlay.style.display = 'block';
}

function hideLogsPopup() {
    const popup = document.getElementById('logs-popup');
    const overlay = document.getElementById('overlay');
    popup.style.display = 'none';
    overlay.style.display = 'none';
}

function showLoginsPopup() {
    socket.emit('logins');
    const popup = document.getElementById('logins-popup');
    const overlay = document.getElementById('overlay');
    popup.style.display = 'block';
    overlay.style.display = 'block';
}

function hideLoginsPopup() {
    const popup = document.getElementById('logins-popup');
    const overlay = document.getElementById('overlay');
    popup.style.display = 'none';
    overlay.style.display = 'none';
}

socket.on('logins_data', data => {
    const loginsList = document.getElementById('logins-list');
    loginsList.innerHTML = '';
    for (const [login, password] of Object.entries(data.logins)) {
        const loginItem = document.createElement('div');
        loginItem.className = 'login-item';
        loginItem.innerHTML = `
            <span class="login-name">${login}</span>
            <button class="toggle-password-btn" onclick="togglePassword(this, '${login}', '${password}')">
                <i class="fa-solid fa-eye"></i>
            </button>
        `;
        loginsList.appendChild(loginItem);
    }
});

function togglePassword(button, login, password) {
    const loginName = button.previousElementSibling;
    const isPasswordVisible = loginName.classList.contains('password-visible');
    if (isPasswordVisible) {
        loginName.textContent = login;
        button.innerHTML = '<i class="fa-solid fa-eye"></i>';
    } else {
        loginName.textContent = password;
        button.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
    }
    loginName.classList.toggle('password-visible');
}

function startSharing() {
    const iface = selectedInterface;
    if (iface && interfaces[iface] === 'managed') {
        socket.emit('start_sharing_hashes', { iface });
        document.getElementById('start-sharing-btn').disabled = true;
        document.getElementById('stop-sharing-btn').disabled = false;
        document.getElementById('start-sniff-btn').disabled = true;
        toggleSectionsAvailability(false, ['sniffing']);
    } else if (interfaces[iface] === 'monitor') {
        alert('Interface must be in managed mode to start sharing hashes.');
    } else {
        alert('Please select an interface.');
    }
}

function stopSharing() {
    socket.emit('stop_sharing_hashes');
    document.getElementById('stop-sharing-btn').disabled = true;
}

socket.on('hash_sharing_data', data => {
    if (data.message === 'Hash sharing started') {
        document.getElementById('sniffing-status').innerText = 'Hash sharing started, password: ' + data.password + '\nPlease connect to the network Dot11Pi and visit http://192.168.1.1';
    } else if (data.message === 'Hash sharing stopped') {
        document.getElementById('start-sharing-btn').disabled = false;
        document.getElementById('stop-sharing-btn').disabled = true;
        document.getElementById('start-sniff-btn').disabled = false;
        document.getElementById('sniffing-status').innerText = 'Hash sharing stopped.';
        toggleSectionsAvailability(true);
    }
});

