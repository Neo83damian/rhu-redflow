        // Replaces window.confirm() everywhere with the same styled card used
        // by the Logout modal. Usage: showConfirmBox('message', () => { ...runs on Okay... }, 'Optional Title');
        // SECURITY: turns text into safe HTML text. Every place that builds
        // HTML (innerHTML) from data typed by people — names, addresses,
        // notes, notification messages — wraps that data in esc(), so a value
        // like <img onerror=...> is shown as plain text and can never run as
        // code in an Admin's browser (stored XSS).
        function esc(value) {
            return String(value === undefined || value === null ? '' : value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        // If onConfirm returns a Promise (i.e. it talks to the server), the
        // modal stays open with the Okay button showing a spinner until that
        // promise settles -- so every confirm-then-delete/clear action gets
        // a real, visible loading state instead of the dialog just vanishing
        // while the request is still in flight. Plain (non-Promise, instant)
        // confirmations behave exactly as before.
        function showConfirmBox(message, onConfirm, title) {
            document.getElementById('genericConfirmTitle').innerText = title || 'Please Confirm';
            document.getElementById('genericConfirmMessage').innerText = message;
            const okBtn = document.getElementById('genericConfirmOkBtn');
            const freshBtn = okBtn.cloneNode(true);
            okBtn.parentNode.replaceChild(freshBtn, okBtn);
            const cancelBtn = document.querySelector('#genericConfirmModal .btn-cancel');
            const okOriginalHtml = freshBtn.innerHTML;
            freshBtn.addEventListener('click', () => {
                const result = onConfirm();
                if (result && typeof result.then === 'function') {
                    freshBtn.disabled = true;
                    freshBtn.style.opacity = '0.6';
                    freshBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Please wait...';
                    if (cancelBtn) cancelBtn.disabled = true;
                    result.finally(() => {
                        closeModal('genericConfirmModal');
                        freshBtn.disabled = false;
                        freshBtn.style.opacity = '';
                        freshBtn.innerHTML = okOriginalHtml;
                        if (cancelBtn) cancelBtn.disabled = false;
                    });
                } else {
                    closeModal('genericConfirmModal');
                }
            });
            openModal('genericConfirmModal');
        }

        // ===== SERVER SYNC (shared across every device/user) =====
        // A plain fetch() helper that attaches the CSRF token Laravel needs
        // for POST/PUT/DELETE, and always sends/expects JSON. This is what
        // makes a donor/record created on one device show up for every
        // other Admin/Staff account on any device — the previous version of
        // this file only ever wrote to localStorage, so nothing actually
        // reached the shared database until this was added.
        const FP_EMAIL_FAIL_MSG = 'Unable to send the verification email right now. Please try again in a moment or check your internet Connection.';

        // ===== SESSION EXPIRY =====
        // The server logs a person out after a period of inactivity (or after
        // it restarts). The page, however, used to keep showing the app as if
        // still logged in (it only remembers "logged in" in the browser), so
        // every screen that talks to the server — Audit Log, Export, Change
        // Password — answered with the server's plain "Unauthenticated."
        // That is NOT a wrong password: it means "the server no longer knows
        // who you are". Now the page notices this, clears the local copy of
        // the data, and takes the person back to the login screen.
        let sessionExpiredHandled = false;

        function wipeLocalAppData() {
            localStorage.removeItem('redflow_logged_in');
            localStorage.removeItem('redflow_current_user');
            ['redflow_donors_masterlist', 'redflow_monitoring_records', 'redflow_audit_log',
             'redflow_notifications', 'redflow_system_users'
            ].forEach(key => localStorage.removeItem(key));
            donorsData = [];
            monitoringRecords = [];
            systemUsers = [];
        }

        function handleSessionExpired() {
            if (sessionExpiredHandled) return;
            sessionExpiredHandled = true;
            try { clearInterval(exportLockTimer); } catch (e) {}
            ['exportPasswordModal', 'genericConfirmModal'].forEach(id => {
                const m = document.getElementById(id);
                if (m) closeModal(id);
            });
            wipeLocalAppData();
            document.getElementById('mainAppContainer').style.display = 'none';
            document.getElementById('loginView').classList.remove('hidden');
            showAlertBox('Your session has expired. Please log in again.');
        }

        function apiRequest(url, method = 'GET', body = null, _isRetry = false) {
            const csrfMeta = document.querySelector('meta[name="csrf-token"]');
            const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
            if (csrfMeta) headers['X-CSRF-TOKEN'] = csrfMeta.content;
            return fetch(url, {
                method,
                headers,
                body: body ? JSON.stringify(body) : undefined,
            }).catch(() => {
                // fetch() only rejects when the request never reached the
                // server at all (no internet, DNS failure, server unreachable).
                const netErr = new Error('No internet connection. Please check your connection and try again.');
                netErr.isNetworkError = true;
                throw netErr;
            }).then(res => {
                return res.json().catch(() => ({})).then(data => {
                    if (!res.ok) {
                        // A 419 means the CSRF token this page loaded with no
                        // longer matches the session on the server (the
                        // session expired, or the server was restarted since
                        // this page was opened). Try ONCE to silently fetch a
                        // fresh token and replay the request before bothering
                        // the user — most of the time this fixes it without
                        // them ever noticing.
                        if (res.status === 419 && !_isRetry) {
                            return fetch('/csrf-token').then(r => r.json()).then(fresh => {
                                if (csrfMeta && fresh.csrf_token) csrfMeta.content = fresh.csrf_token;
                                return apiRequest(url, method, body, true);
                            });
                        }
                        if (res.status === 419) {
                            const err = new Error('Your session expired. Please refresh the page and log in again.');
                            err.status = 419;
                            throw err;
                        }
                        // 401 "Unauthenticated." on a page that needs a login = session ended.
                        // (Wrong-password replies from /login, /register and the
                        // forgot-password steps are also 401/4xx but are NOT this.)
                        const publicUrl = url === '/login' || url === '/register' || url === '/logout' || url.startsWith('/forgot-password');
                        if (res.status === 401 && !publicUrl) {
                            handleSessionExpired();
                            const err = new Error('Your session has expired. Please log in again.');
                            err.status = 401;
                            err.sessionExpired = true;
                            throw err;
                        }
                        const err = new Error(data.message || ('Request failed: ' + res.status));
                        err.status = res.status;
                        err.data = data;
                        throw err;
                    }
                    return data;
                });
            });
        }

        // Pulls the latest donors + history records from the database and
        // replaces the local cache with them, then re-renders whatever page
        // is currently open. Called on every login/page load, so every
        // device always shows what's actually in the shared database
        // instead of only what this one browser happened to create.
        function hydrateAppDataFromServer() {
            apiRequest('/api/donors').then(data => {
                donorsData = data.donors || [];
                localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                renderDonorCards();
                updateStatisticsData();
            }).catch(() => { /* offline or not logged in yet — keep the local cache as-is */ });

            apiRequest('/api/donation-records').then(data => {
                monitoringRecords = data.records || [];
                localStorage.setItem('redflow_monitoring_records', JSON.stringify(monitoringRecords));
                renderMonitoringTable();
                updateStatisticsData();
            }).catch(() => {});

            apiRequest('/api/users').then(data => {
                systemUsers = data.users || [];
                localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                renderAdminApprovalPageView();
                renderUsersLogView();
            }).catch(() => {});

            apiRequest('/api/notifications').then(data => {
                if (data && data.notifications) {
                    const store = loadNotificationsStore();
                    Object.assign(store, data.notifications);
                    saveNotificationsStore(store);
                    updateNotificationBadge();
                    renderNotificationsView();
                }
            }).catch(() => {});

            apiRequest('/api/audit-log').then(data => {
                if (data && data.entries) {
                    localStorage.setItem('redflow_audit_log', JSON.stringify(data.entries));
                    renderAuditLogView();
                }
            }).catch(() => {});
        }

        // SYSTEM ACCOUNTS DATA STORE — hydrated from /api/users on load (see
        // the fetch block below). No accounts are hardcoded here; every
        // Admin/Staff account is created through Sign Up or the database
        // seeder, never baked into this file.
        let systemUsers = JSON.parse(localStorage.getItem('redflow_system_users')) || [];

        // GLOBAL DONORS DATA STORE — hydrated from /api/donors on load. No
        // sample donors are hardcoded here; every donor comes from the
        // Create Donor form, stored in the database.
        let donorsData = JSON.parse(localStorage.getItem('redflow_donors_masterlist')) || [];

        // Hydrated from /api/donation-records on load. No sample history
        // records are hardcoded here.
        let monitoringRecords = JSON.parse(localStorage.getItem('redflow_monitoring_records')) || [];

        // The logged-in user's own Account Information — populated from the
        // server response on login/profile load. No placeholder person is
        // hardcoded here.
        let staffData = JSON.parse(localStorage.getItem('redflow_staff_profile')) || {
            name: "",
            role: "Staff",
            sex: "",
            bday: "",
            address: "",
            email: "",
            contact: "",
            avatar: "picture.jpg"
        };

        let isViewingStaff = true;
        let activeSelectedDonorId = null;

        // PERSISTENT LOGIN CHECK ON DOM LOAD
        window.addEventListener('DOMContentLoaded', () => {
            const isLoggedIn = localStorage.getItem('redflow_logged_in');
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            if (isLoggedIn === 'true' && currentUser) {
                document.getElementById('loginView').classList.add('hidden');
                document.getElementById('mainAppContainer').style.display = 'block';
                setupSidebarByRole(currentUser);
                isSidebarOpen = window.innerWidth > 768;
                applySidebarState();
                setTimeout(() => { 
                    renderDonorCards();
                    renderMonitoringTable();
                    renderAdminApprovalPageView();
                    renderUsersLogView();
                    updateNotificationBadge();
                    hydrateAppDataFromServer();
                }, 100);
            }
            setupOtpBoxBehavior('.fp-otp');
            setupOtpBoxBehavior('.cp-otp');
        });

        // ===== OTP INPUT BEHAVIOR: single paste fills all boxes, auto-advance
        // on typing, backspace moves back. Attached once at load since the
        // OTP boxes are static markup already in the DOM. =====
        function setupOtpBoxBehavior(selector) {
            const boxes = Array.from(document.querySelectorAll(selector));
            if (boxes.length === 0) return;
            boxes.forEach((box, i) => {
                box.addEventListener('input', () => {
                    const digits = box.value.replace(/\D/g, '');
                    if (digits.length > 1) {
                        // Handles the case where a paste lands as an 'input'
                        // event instead of a 'paste' event on some browsers.
                        distributeOtpDigits(boxes, i, digits);
                        return;
                    }
                    box.value = digits;
                    if (digits && i < boxes.length - 1) boxes[i + 1].focus();
                });
                box.addEventListener('keydown', (e) => {
                    if (e.key === 'Backspace' && !box.value && i > 0) {
                        boxes[i - 1].focus();
                    }
                });
                box.addEventListener('paste', (e) => {
                    e.preventDefault();
                    const pasted = (e.clipboardData || window.clipboardData).getData('text');
                    const digits = pasted.replace(/\D/g, '');
                    if (!digits) return;
                    distributeOtpDigits(boxes, 0, digits);
                });
            });
        }

        function distributeOtpDigits(boxes, startIndex, digits) {
            let d = 0;
            for (let i = startIndex; i < boxes.length && d < digits.length; i++, d++) {
                boxes[i].value = digits[d];
            }
            const nextEmpty = boxes.findIndex(b => !b.value);
            (nextEmpty === -1 ? boxes[boxes.length - 1] : boxes[nextEmpty]).focus();
        }

        function setupSidebarByRole(user) {
            const sidebarMenuContainer = document.getElementById('sidebarMenuContainer');
            if (!sidebarMenuContainer) return;

            if (user && user.role === 'Admin') {
                sidebarMenuContainer.innerHTML = `
                    <button class="side-custom-btn" onclick="switchMainPage('home', this)"><i class="fa-solid fa-list-check" style="margin-right:8px;"></i> Donor Masterlist</button>
                    <button class="side-custom-btn" onclick="switchMainPage('statistics', this); updateStatisticsData();"><i class="fa-solid fa-chart-pie" style="margin-right:8px;"></i> Statistics Dashboard</button>
                    <button class="side-custom-btn" onclick="switchMainPage('approvals', this); renderAdminApprovalPageView();"><i class="fa-solid fa-user-check" style="margin-right:8px;"></i> Approval Verification</button>
                    <button class="side-custom-btn" onclick="switchMainPage('userslog', this); renderUsersLogView();"><i class="fa-solid fa-users-rectangle" style="margin-right:8px;"></i> Users Log</button>
                    <button class="side-custom-btn" onclick="switchMainPage('auditlog', this); renderAuditLogView(); refreshAuditLogFromServer();"><i class="fa-solid fa-shield-halved" style="margin-right:8px;"></i> Audit Log</button>
                    <button class="side-custom-btn" style="background-color:var(--success-green);" onclick="openExportPasswordModal()"><i class="fa-solid fa-file-export" style="margin-right:8px;"></i> Export Masterlist</button>
                    <button class="side-custom-btn" onclick="toggleDarkMode()"><i class="fa-solid fa-moon" style="margin-right:8px;"></i> Dark Mode</button>
                    <button class="side-custom-btn" onclick="switchMainPage('settings', this); resetChangePasswordFlow();"><i class="fa-solid fa-lock" style="margin-right:8px;"></i> Account Security</button>
                `;
            } else {
                sidebarMenuContainer.innerHTML = `
                    <button class="side-custom-btn" onclick="switchMainPage('home', this)"><i class="fa-solid fa-list-check" style="margin-right:8px;"></i> Donor Masterlist</button>
                    <button class="side-custom-btn" onclick="toggleDarkMode()"><i class="fa-solid fa-moon" style="margin-right:8px;"></i> Dark Mode</button>
                    <button class="side-custom-btn" onclick="switchMainPage('about', this); loadSubModule('faq')"><i class="fa-solid fa-circle-question" style="margin-right:8px;"></i> FAQ</button>
                    <button class="side-custom-btn" onclick="switchMainPage('settings', this); resetChangePasswordFlow();"><i class="fa-solid fa-lock" style="margin-right:8px;"></i> Account Security</button>
                `;
            }
        }
        function updateStatisticsData() {
            const totalPendingElem = document.getElementById('statTotalPending');
            const numberAdminElem = document.getElementById('statNumberAdmin');
            const numberStaffElem = document.getElementById('statNumberStaff');
            const numberDonorsElem = document.getElementById('statNumberDonors');
            if (totalPendingElem) {
                const pendingCount = systemUsers.filter(u => u.role === 'Staff' && u.status === 'Pending').length;
                totalPendingElem.innerText = pendingCount;
            }
            if (numberAdminElem) numberAdminElem.innerText = systemUsers.filter(u => u.role === 'Admin').length;
            if (numberStaffElem) numberStaffElem.innerText = systemUsers.filter(u => u.role === 'Staff' && u.status === 'Approved').length;
            if (numberDonorsElem) numberDonorsElem.innerText = donorsData.length;
            const numberHistoryElem = document.getElementById('statNumberHistory');
            if (numberHistoryElem) numberHistoryElem.innerText = monitoringRecords.length;

            // Number of Notification: the CURRENTLY LOGGED-IN account's own
            // notification count (not a cross-user total) — shows a plain
            // "0" when there are none, never blank/undefined.
            const numberNotificationsElem = document.getElementById('statNumberNotifications');
            if (numberNotificationsElem) {
                numberNotificationsElem.innerText = getCurrentUserNotifications().length || 0;
            }
            const numberAuditLogElem = document.getElementById('statNumberAuditLog');
            if (numberAuditLogElem) {
                const auditLog = JSON.parse(localStorage.getItem('redflow_audit_log')) || [];
                numberAuditLogElem.innerText = auditLog.length;
            }
            const numberUserLogElem = document.getElementById('statNumberUserLog');
            if (numberUserLogElem) numberUserLogElem.innerText = systemUsers.length;
            const monthlyDateInput = document.getElementById('monthlyDonationsDate');
            const todayStr = new Date().toISOString().split('T')[0];
            if (monthlyDateInput && !monthlyDateInput.value) monthlyDateInput.value = todayStr;
            if (monthlyDateInput) renderMonthlyDonationsChart(monthlyDateInput.value.split('-')[0]);
            renderBloodTypeAvailability();
        }
        function renderMonthlyDonationsChart(year) {
            const chartElem = document.getElementById('monthlyDonationsChart');
            const labelsElem = document.getElementById('monthlyDonationsLabels');
            if (!chartElem || !labelsElem) return;
            const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
            const counts = new Array(12).fill(0);
            // NOTE: Counts are built from each record's completed transaction
            // history PLUS its current donation (donationDate) -- see below.
            // This makes a History Record count toward Monthly Donations
            // immediately when it's created/updated, under whichever year
            // the donation date falls in, while still correctly subtracting
            // a record's totals the moment that History Record is deleted
            // (since both its transactions and its current donation leave
            // the pool with it).
            monitoringRecords.forEach(rec => {
                if (Array.isArray(rec.transactions)) {
                    rec.transactions.forEach(tx => {
                        if (tx.date && tx.date.startsWith(String(year))) {
                            const monthIdx = parseInt(tx.date.split('-')[1], 10) - 1;
                            if (monthIdx >= 0 && monthIdx < 12) counts[monthIdx]++;
                        }
                    });
                }
                // UPDATED: also count the record's current donation (donationDate)
                // itself, not just its past/superseded transactions. This is what
                // makes a newly created or updated History Record show up in
                // Monthly Donations right away, under whatever year it was made
                // in. When that donation is later superseded, it moves into
                // "transactions" above and the new one takes its place here, so
                // every real donation is still counted exactly once. Deleting the
                // History Record removes this record entirely, so the count goes
                // back down correctly.
                if (rec.donationDate && rec.donationDate !== 'N/A' && rec.donationDate.startsWith(String(year))) {
                    const monthIdx = parseInt(rec.donationDate.split('-')[1], 10) - 1;
                    if (monthIdx >= 0 && monthIdx < 12) counts[monthIdx]++;
                }
            });
            const maxCount = Math.max(...counts, 1);
            chartElem.innerHTML = counts.map(c => {
                const pct = c > 0 ? (c / maxCount * 100) : 0;
                return `
                <div class="monthly-chart-col">
                    <div class="monthly-chart-track">
                        <div class="monthly-chart-count" style="bottom:calc(${pct}% + 4px);">${c}</div>
                        <div class="monthly-chart-bar" style="height:${pct}%;"></div>
                    </div>
                </div>`;
            }).join('');
            labelsElem.innerHTML = monthNames.map(m => `<span>${m}</span>`).join('');
        }
        function renderBloodTypeAvailability() {
            const listElem = document.getElementById('bloodTypeAvailabilityList');
            if (!listElem) return;
            const bloodTypes = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];
            const countByType = {};
            bloodTypes.forEach(bt => countByType[bt] = 0);
            donorsData.forEach(donor => {
                if (countByType.hasOwnProperty(donor.bloodType)) {
                    countByType[donor.bloodType]++;
                }
            });
            const maxCount = Math.max(...Object.values(countByType), 1);
            listElem.innerHTML = bloodTypes.map(bt => `
                <div class="blood-avail-row">
                    <div class="blood-avail-row-top">
                        <span>${bt}</span>
                        <span>${countByType[bt]}</span>
                    </div>
                    <div class="blood-avail-track">
                        <div class="blood-avail-fill" style="width:${(countByType[bt] / maxCount * 100)}%;"></div>
                    </div>
                </div>
            `).join('');
        }

        function renderAdminApprovalPageView() {
            const container = document.getElementById('adminApprovalPageViewList');
            if (!container) return;

            const pendingStaff = systemUsers.filter(u => u.role === 'Staff' && u.status === 'Pending');
            if (pendingStaff.length === 0) {
                container.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);">No pending staff approvals at this time.</div>';
                return;
            }

            container.innerHTML = `
                <table class="approval-table">
                    <thead>
                        <tr>
                            <th>User Role</th>
                            <th>Name</th>
                            <th>Contact / Location</th>
                            <th>ID Front</th>
                            <th>ID Back</th>
                            <th>Face Document</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pendingStaff.map(staff => {
                            const idFront = staff.idFront || 'picture.jpg';
                            const idBack = staff.idBack || 'picture.jpg';
                            const faceDoc = staff.faceDoc || 'picture.jpg';
                            return `
                            <tr>
                                <td><span class="approval-role-badge">${esc(staff.role)}</span></td>
                                <td style="font-weight:bold;">${esc(staff.name)}</td>
                                <td>
                                    <div>${esc(staff.email)}</div>
                                    <div style="color:var(--text-muted); font-size:12px;">${esc(staff.contact || '')}${staff.brgy ? ' | Brgy. ' + esc(staff.brgy) : ''}</div>
                                </td>
                                <td><img class="approval-doc-thumb" src="${esc(idFront)}" onerror="this.src='picture.jpg'" onclick="openImageZoom('${esc(idFront)}')"></td>
                                <td><img class="approval-doc-thumb" src="${esc(idBack)}" onerror="this.src='picture.jpg'" onclick="openImageZoom('${esc(idBack)}')"></td>
                                <td><img class="approval-doc-thumb" src="${esc(faceDoc)}" onerror="this.src='picture.jpg'" onclick="openImageZoom('${esc(faceDoc)}')"></td>
                                <td>
                                    <button onclick="approveStaff('${esc(staff.id)}')" style="background:var(--success-green); color:white; border:none; padding:7px 12px; border-radius:6px; font-weight:bold; cursor:pointer; margin-right:6px; font-size:12px; white-space:nowrap;"><i class="fa-solid fa-check"></i> Approve</button>
                                    <button onclick="rejectStaff('${esc(staff.id)}')" style="background:var(--primary-red); color:white; border:none; padding:7px 12px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:12px; white-space:nowrap;"><i class="fa-solid fa-xmark"></i> Reject</button>
                                </td>
                            </tr>
                        `}).join('')}
                    </tbody>
                </table>
            `;
        }

        function openImageZoom(src) {
            document.getElementById('imageZoomTarget').src = src;
            document.getElementById('imageZoomOverlay').style.display = 'flex';
        }

        function closeImageZoom() {
            document.getElementById('imageZoomOverlay').style.display = 'none';
        }

        function isAdminUser() {
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            return !!(currentUser && currentUser.role === 'Admin');
        }

        let selectedUserIds = new Set();
        let currentRenderedUserIds = [];

        function renderUsersLogView() {
            const container = document.getElementById('usersLogContainer');
            if (!container) return;
            const adminMode = isAdminUser();

            currentRenderedUserIds = systemUsers.map(u => u.id);
            selectedUserIds.clear();
            refreshUsersDeleteBtn();
            const bulkBar = document.getElementById('usersBulkBar');
            if (bulkBar) bulkBar.style.display = adminMode ? 'flex' : 'none';
            const selectAllBox = document.getElementById('usersSelectAll');
            if (selectAllBox) selectAllBox.checked = false;

            if (systemUsers.length === 0) {
                container.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);">No registered users found.</div>';
                return;
            }

            container.innerHTML = `
                <div class="approval-table-wrapper">
                    <table class="approval-table">
                        <thead>
                            <tr>
                                ${adminMode ? `<th style="width:30px;"></th>` : ''}
                                <th>Timestamp</th>
                                <th>User Name</th>
                                <th>User Role</th>
                                <th>Contact</th>
                                <th>Action Taken</th>
                                ${adminMode ? `<th>Action</th>` : ''}
                            </tr>
                        </thead>
                        <tbody>
                            ${systemUsers.map(user => `
                                <tr>
                                    ${adminMode ? `<td><input type="checkbox" class="admin-row-checkbox" style="margin-right:0;" onchange="toggleUserSelect('${esc(user.id)}', this.checked)"></td>` : ''}
                                    <td style="white-space:nowrap;">${formatLoginTimestamp(user.registeredAt)}</td>
                                    <td style="font-weight:bold;">${esc(user.name)}</td>
                                    <td><span style="font-size:11px; background:${user.role === 'Admin' ? 'var(--primary-red)' : 'var(--sidebar-btn-bg)'}; color:white; padding:2px 8px; border-radius:4px;">${esc(user.role)}</span></td>
                                    <td>${esc(user.contact || 'N/A')}</td>
                                    <td>
                                        ${esc(user.actionTaken || 'Registered')}
                                        <span style="display:block; font-size:11px; font-weight:bold; margin-top:2px; color:${user.status === 'Approved' ? '#2e7d32' : '#f57f17'};">${esc(user.status || 'Approved')}</span>
                                        ${user.status === 'Approved' && user.approvedBy ? `<span style="display:block; font-size:10px; color:var(--text-muted); margin-top:2px;">Approved by: ${esc(user.approvedBy)}</span>` : ''}
                                    </td>
                                    ${adminMode ? `<td><button class="admin-bulk-delete-btn active" style="padding:6px 12px;" onclick="deleteSingleUser('${esc(user.id)}')"><i class="fa-solid fa-trash"></i> DELETE</button></td>` : ''}
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        function deleteSingleUser(userId) {
            const targetUser = systemUsers.find(u => u.id === userId);
            if (targetUser && targetUser.role === 'Admin' && systemUsers.filter(u => u.role === 'Admin').length <= 1) {
                showAlertBox('The last remaining Admin account cannot be deleted.');
                return;
            }
            showConfirmBox('Are you sure you want to delete this user account?', () => {
                // Waits for the server to confirm the account is actually
                // gone (the Okay button shows a spinner the whole time) before
                // removing it from the list — without this, the account only
                // looked deleted on this one device/browser and could still
                // log in and would still show up for every other Admin/Staff.
                return apiRequest('/api/users/' + userId, 'DELETE').then(() => {
                    systemUsers = systemUsers.filter(u => u.id !== userId);
                    localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                    renderUsersLogView();
                    updateStatisticsData();
                }).catch(err => {
                    showAlertBox(err.message || 'Could not delete this user from the database. Please try again.');
                });
            }, 'Delete User');
        }

        function formatLoginTimestamp(isoString) {
            if (!isoString) return 'Not yet logged in';
            const dateObj = new Date(isoString);
            if (isNaN(dateObj.getTime())) return 'Not yet logged in';
            const datePart = dateObj.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
            const timePart = dateObj.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
            return `${datePart}, ${timePart}`;
        }

        // ============ ACCOUNT NOTIFICATIONS (per-user login activity & approval alerts) ============
        function loadNotificationsStore() {
            return JSON.parse(localStorage.getItem('redflow_notifications')) || {};
        }

        function saveNotificationsStore(store) {
            localStorage.setItem('redflow_notifications', JSON.stringify(store));
        }

        // Adds a notification entry for a specific user account (by user id).
        function pushNotification(userId, message) {
            if (!userId) return;
            const store = loadNotificationsStore();
            if (!store[userId]) store[userId] = [];
            store[userId].unshift({
                id: 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
                message: message,
                timestamp: new Date().toISOString(),
                read: false
            });
            saveNotificationsStore(store);
            updateNotificationBadge();
        }

        function getCurrentUserNotifications() {
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            if (!currentUser) return [];
            const store = loadNotificationsStore();
            return store[currentUser.id] || [];
        }

        // Shows a number badge on the bottom nav "Notification" icon with
        // the count of unread notifications — like Facebook, not just a dot
        // — and hides it entirely when there are none.
        function updateNotificationBadge() {
            const dot = document.getElementById('notifBadgeDot');
            if (!dot) return;
            const unreadCount = getCurrentUserNotifications().filter(n => !n.read).length;
            if (unreadCount > 0) {
                dot.innerText = unreadCount > 99 ? '99+' : unreadCount;
                dot.style.display = 'block';
            } else {
                dot.style.display = 'none';
            }
        }

        // Renders the logged-in user's own notifications: who logged in / used
        // their account, and (for Staff) their account approval message.
        function renderNotificationsView() {
            const container = document.getElementById('notificationsListContainer');
            if (!container) return;
            const notifs = getCurrentUserNotifications();

            if (notifs.length === 0) {
                container.innerHTML = `<p style="text-align:center; color:var(--text-muted); padding:30px 10px;">No notifications yet.</p>`;
            } else {
                container.innerHTML = notifs.map(n => `
                    <div class="notif-item ${n.read ? '' : 'unread'}">
                        <div class="notif-item-main">
                            <div class="notif-item-icon"><i class="fa-solid fa-bell"></i></div>
                            <div>
                                <p class="notif-item-message">${esc(n.message)}</p>
                                <span class="notif-item-time">${formatLoginTimestamp(n.timestamp)}</span>
                            </div>
                        </div>
                        <div class="notif-item-actions">
                            <button class="notif-item-read-btn" aria-label="${n.read ? 'Mark as unread' : 'Mark as read'}" onclick="setNotificationRead('${esc(n.id)}', ${n.read ? 'false' : 'true'})"><i class="fa-solid ${n.read ? 'fa-envelope' : 'fa-envelope-open'}"></i></button>
                            <button class="notif-item-delete-btn" title="Delete notification" onclick="deleteNotification('${esc(n.id)}')"><i class="fa-solid fa-trash"></i></button>
                        </div>
                    </div>
                `).join('');
            }
            updateNotificationBadge();
        }

        // Marks every one of the logged-in account's notifications as read.
        // Only call this when the account owner has actually opened the
        // Notification page (see the bottom-nav button's onclick) — NOT
        // from background hydration on login/page-load, or every
        // notification would already show as "read" (no red left-border
        // highlight) before the person ever laid eyes on the page, which
        // was exactly the bug here before this fix.
        function markNotificationsAsRead() {
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            if (!currentUser) return;
            const store = loadNotificationsStore();
            if (store[currentUser.id]) {
                store[currentUser.id].forEach(n => n.read = true);
                saveNotificationsStore(store);
            }
            updateNotificationBadge();
        }

        // Marks ONE notification as read (or back to unread) — only when the
        // person taps the envelope icon AND confirms. Opening the Notification
        // page no longer marks everything as read by itself, so an unread
        // notification keeps its red lit edge until it is marked as read.
        function setNotificationRead(notifId, makeRead) {
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            if (!currentUser) return;
            showConfirmBox(makeRead ? 'This notification will be marked as read.' : 'This notification will be marked as unread.', () => {
                const store = loadNotificationsStore();
                const list = store[currentUser.id] || [];
                const n = list.find(x => x.id === notifId);
                if (!n) return;
                n.read = makeRead;
                saveNotificationsStore(store);
                renderNotificationsView();
                updateNotificationBadge();
                apiRequest('/api/notifications/' + notifId + '/read', 'PATCH', { read: makeRead }).catch(() => {
                    showAlertBox('Warning: Could not save this change to the server. If you are offline, it may go back after you log in again — please try again once you are back online.');
                });
            }, makeRead ? 'Mark as Read' : 'Mark as Unread');
        }

        // Lets the logged-in account owner (Staff or Admin) delete a single
        // notification of their own — removed immediately and permanently
        // (no grace period; the Number of Notification count on the
        // Statistics Dashboard is what tracks volume instead).
        function deleteNotification(notifId) {
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            if (!currentUser) return;
            showConfirmBox('Delete this notification? It will be permanently deleted.', () => {
                const store = loadNotificationsStore();
                if (!store[currentUser.id]) return;
                store[currentUser.id] = store[currentUser.id].filter(n => n.id !== notifId);
                saveNotificationsStore(store);
                renderNotificationsView();
                updateStatisticsData();
                updateNotificationBadge();
                // If this server call fails, the notification is NOT
                // actually deleted in the database — it would reappear on
                // the next login/hydration. Warn instead of failing
                // silently, so that never looks like an unexplained "it
                // came back" bug.
                apiRequest('/api/notifications/' + notifId, 'DELETE').catch(() => {
                    showAlertBox('Warning: Could not confirm the delete with the server. If you are offline, this notification may reappear after you log back in — please try again once you are back online.');
                });
            }, 'Delete Notification');
        }

        // Lets the logged-in account owner clear all of their own
        // notifications at once — removed immediately and permanently.
        function clearAllNotifications() {
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            if (!currentUser) return;
            const notifs = getCurrentUserNotifications();
            if (notifs.length === 0) return;
            showConfirmBox('Delete all your notifications? They will be permanently deleted.', () => {
                const store = loadNotificationsStore();
                store[currentUser.id] = [];
                saveNotificationsStore(store);
                renderNotificationsView();
                updateStatisticsData();
                updateNotificationBadge();
                apiRequest('/api/notifications', 'DELETE').catch(() => {
                    showAlertBox('Warning: Could not confirm the delete with the server. If you are offline, these notifications may reappear after you log back in — please try again once you are back online.');
                });
            }, 'Clear All Notifications');
        }

        function toggleUserSelect(id, checked) {
            if (checked) selectedUserIds.add(id); else selectedUserIds.delete(id);
            refreshUsersDeleteBtn();
        }

        function refreshUsersDeleteBtn() {
            const btn = document.getElementById('usersDeleteBtn');
            if (!btn) return;
            btn.innerHTML = `<i class="fa-solid fa-trash"></i> DELETE (${selectedUserIds.size})`;
            btn.classList.toggle('active', selectedUserIds.size > 0);
        }

        function toggleSelectAllUsers(checked) {
            document.querySelectorAll('#usersLogContainer .admin-row-checkbox').forEach(cb => cb.checked = checked);
            if (checked) currentRenderedUserIds.forEach(id => selectedUserIds.add(id));
            else selectedUserIds.clear();
            refreshUsersDeleteBtn();
        }

        function deleteSelectedUsers() {
            if (selectedUserIds.size === 0) return;
            const idsArray = Array.from(selectedUserIds);
            const selectedAdmins = systemUsers.filter(u => idsArray.includes(u.id) && u.role === 'Admin');
            const totalAdmins = systemUsers.filter(u => u.role === 'Admin').length;
            if (selectedAdmins.length > 0 && selectedAdmins.length >= totalAdmins) {
                showAlertBox('The last remaining Admin account cannot be deleted.');
                return;
            }
            showConfirmBox(`Are you sure you want to delete ${selectedUserIds.size} selected user(s)?`, () => {
                return apiRequest('/api/users/bulk', 'DELETE', { ids: idsArray }).then(data => {
                    systemUsers = systemUsers.filter(u => !selectedUserIds.has(u.id));
                    localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                    selectedUserIds.clear();
                    renderUsersLogView();
                    updateStatisticsData();
                    if (data && data.skipped && data.skipped.length > 0) {
                        showAlertBox('Note: ' + data.skipped.join(', ') + ' was not deleted (last remaining Admin account).');
                    }
                }).catch(err => {
                    showAlertBox(err.message || 'Could not delete these users from the database. Please try again.');
                });
            }, 'Delete Users');
        }

        // ============ LOGIN LOCKOUT (5 failed attempts = 60 second wait) ============
        const LOGIN_MAX_ATTEMPTS = 5;
        const LOGIN_LOCKOUT_MS = 60000;

        function getLoginAttemptsStore() {
            return JSON.parse(localStorage.getItem('redflow_login_attempts')) || {};
        }
        function saveLoginAttemptsStore(store) {
            localStorage.setItem('redflow_login_attempts', JSON.stringify(store));
        }
        // Returns remaining lockout seconds (0 if not locked) for this email.
        function getRemainingLockoutSeconds(email) {
            const store = getLoginAttemptsStore();
            const entry = store[email];
            if (!entry || !entry.lockUntil) return 0;
            const remainingMs = entry.lockUntil - Date.now();
            return remainingMs > 0 ? Math.ceil(remainingMs / 1000) : 0;
        }
        function registerFailedLoginAttempt(email) {
            const store = getLoginAttemptsStore();
            const entry = store[email] || { count: 0, lockUntil: 0 };
            entry.count = (entry.count || 0) + 1;
            if (entry.count >= LOGIN_MAX_ATTEMPTS) {
                entry.lockUntil = Date.now() + LOGIN_LOCKOUT_MS;
                entry.count = 0;
            }
            store[email] = entry;
            saveLoginAttemptsStore(store);
        }
        function clearFailedLoginAttempts(email) {
            const store = getLoginAttemptsStore();
            if (store[email]) {
                delete store[email];
                saveLoginAttemptsStore(store);
            }
        }

        function handleLogin() {
            const email = document.getElementById('loginEmail').value.trim().toLowerCase();
            const password = document.getElementById('loginPassword').value;
            const loginBtn = document.querySelector('#loginView .login-btn, #loginView .action-main-btn, #loginView button[onclick="handleLogin()"]');
            const loginBtnOriginalText = loginBtn ? loginBtn.innerHTML : '';
            if (loginBtn) {
                loginBtn.disabled = true;
                loginBtn.style.opacity = '0.7';
                loginBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Logging in...';
            }

            // Real server-side login: checks bcrypt password hash, the
            // 5-attempt/60-second lockout, and Pending-approval status in
            // the actual database — this used to be a purely client-side
            // check against a localStorage array (including a hardcoded
            // fallback admin/admin123), which is why nothing a Staff member
            // did ever showed up on the Admin's own device: there was never
            // really a shared session or shared data being read at all.
            apiRequest('/login', 'POST', { email, password }).then(data => {
                const user = data.user;
                const csrfMeta = document.querySelector('meta[name="csrf-token"]');
                if (csrfMeta && data.csrf_token) csrfMeta.content = data.csrf_token;

                sessionExpiredHandled = false;
                localStorage.setItem('redflow_logged_in', 'true');
                localStorage.setItem('redflow_current_user', JSON.stringify(user));

                // Sync staff profile display
                staffData.name = user.name;
                staffData.role = user.role;
                staffData.email = user.email || staffData.email;
                staffData.contact = user.contact || staffData.contact;
                localStorage.setItem('redflow_staff_profile', JSON.stringify(staffData));

                document.getElementById('loginView').classList.add('hidden');
                document.getElementById('mainAppContainer').style.display = 'block';

                setupSidebarByRole(user);
                isSidebarOpen = window.innerWidth > 768;
                applySidebarState();

                setTimeout(() => {
                    renderDonorCards();
                    renderMonitoringTable();
                    renderAdminApprovalPageView();
                    renderUsersLogView();
                    updateNotificationBadge();
                    hydrateAppDataFromServer();
                }, 100);
                showAlertBox(`Logged in successfully as ${user.role}!`);
            }).catch(err => {
                showAlertBox(err.message || 'Error: Incorrect Email or Password! Please check your credentials.');
            }).finally(() => {
                if (loginBtn) { loginBtn.disabled = false; loginBtn.style.opacity = '1'; loginBtn.innerHTML = loginBtnOriginalText; }
            });
        }

        // ============ STAFF SIGN UP WIZARD (8 steps, ID + Selfie verification) ============
        let suData = {};
        let suSelfieStream = null;
        let suSelfieCaptured = false;

        function openSignupWizard() {
            // Reset all wizard state and fields every time it's opened fresh.
            suData = { frontId: null, backId: null, faceDoc: null };
            suSelfieCaptured = false;
            const ids = ['suFullname','suContact','suDob','suGender','suBrgy','suEmail','suPassword','suConfirmPassword'];
            ids.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
            document.getElementById('suTermsConsent').checked = false;
            document.getElementById('suPrivacyConsent').checked = false;
            document.getElementById('suIdFrontStatus').textContent = 'Tap to take photo or upload';
            document.getElementById('suIdFrontStatus').style.color = '';
            document.getElementById('suIdFrontPreview').style.display = 'none';
            document.getElementById('suIdBackStatus').textContent = 'Tap to take photo or upload';
            document.getElementById('suIdBackStatus').style.color = '';
            document.getElementById('suIdBackPreview').style.display = 'none';
            goToSignupStep(1);
            openModal('signupModal');
        }

        function closeSignupWizard() {
            stopSuSelfieCamera();
            closeModal('signupModal');
        }

        // ============ FORGOT PASSWORD (email OTP recovery) ============
        let fpVerifiedCode = '';
        let fpTargetEmail = '';

        function openForgotPasswordModal() {
            fpVerifiedCode = '';
            fpTargetEmail = '';
            document.getElementById('fpEmailInput').value = '';
            document.querySelectorAll('.fp-otp').forEach(input => input.value = '');
            document.getElementById('fpNewPassword').value = '';
            document.getElementById('fpConfirmPassword').value = '';
            goToFpStep(1);
            openModal('forgotPasswordModal');
        }

        function closeForgotPasswordModal() {
            closeModal('forgotPasswordModal');
        }

        function goToFpStep(stepNumber) {
            document.querySelectorAll('#forgotPasswordModal .su-step').forEach(panel => panel.classList.remove('active'));
            document.getElementById('fp-step-' + stepNumber).classList.add('active');
        }

        function validateFpStep1() {
            const email = document.getElementById('fpEmailInput').value.trim().toLowerCase();
            if (!email) {
                showAlertBox('Please enter your registered email address.');
                return;
            }

            fpTargetEmail = email;

            const btn = document.getElementById('fpSendCodeBtn');
            btn.textContent = 'Sending...';
            btn.disabled = true;

            // Real backend now (AuthController::sendOtp) — this used to call
            // a third-party "EmailJS" service with literal placeholder IDs
            // ("YOUR_SERVICE_ID"/"YOUR_TEMPLATE_ID") that was never actually
            // configured and whose script wasn't even loaded on the page, so
            // clicking "Send Code" crashed immediately with "emailjs is not
            // defined" and never sent anything. The server already has a
            // complete, working OTP system (hashed codes, 10-minute expiry,
            // real email via Laravel Mail) — this was just never wired up to
            // it on the frontend.
            apiRequest('/forgot-password/send-otp', 'POST', { email: email }).then(() => {
                document.getElementById('fpEmailTargetText').textContent = `Check ${email} for your 6-digit code.`;
                btn.textContent = 'Send Code';
                btn.disabled = false;
                goToFpStep(2);
            }).catch(err => {
                showAlertBox(err.isNetworkError ? FP_EMAIL_FAIL_MSG : (err.message || FP_EMAIL_FAIL_MSG));
                btn.textContent = 'Send Code';
                btn.disabled = false;
            });
        }

        // Shared by both "Resend" links (Forgot Password and Change Password).
        // Reacts the instant it is clicked ("Sending..."), blocks accidental
        // double-clicks, and then shows a short countdown before it can be
        // used again (this also protects the email service from spam).
        const RESEND_COOLDOWN_SECONDS = 10;

        function startResendCooldown(btn, seconds) {
            let left = seconds;
            btn.disabled = true;
            btn.textContent = `Resend in ${left}s`;
            const timer = setInterval(() => {
                left--;
                if (left <= 0) {
                    clearInterval(timer);
                    btn.disabled = false;
                    btn.textContent = 'Resend';
                } else {
                    btn.textContent = `Resend in ${left}s`;
                }
            }, 1000);
        }

        function resendOtpWithFeedback(btn, url, email, sentMessage, onNoEmail) {
            if (btn && btn.disabled) return;
            if (!email) { if (onNoEmail) onNoEmail(); return; }
            if (!navigator.onLine) { showAlertBox(FP_EMAIL_FAIL_MSG); return; }
            if (btn) { btn.disabled = true; btn.textContent = 'Sending...'; }
            apiRequest(url, 'POST', { email: email }).then(() => {
                if (btn) startResendCooldown(btn, RESEND_COOLDOWN_SECONDS);
                showAlertBox(sentMessage);
            }).catch(err => {
                if (btn) { btn.disabled = false; btn.textContent = 'Resend'; }
                showAlertBox(err.isNetworkError ? FP_EMAIL_FAIL_MSG : (err.message || FP_EMAIL_FAIL_MSG));
            });
        }

        function resendFpCode(btn) {
            resendOtpWithFeedback(btn, '/forgot-password/send-otp', fpTargetEmail,
                `A new verification code has been resent to ${fpTargetEmail}.`,
                () => goToFpStep(1));
        }

        function validateFpStep2(event) {
            const otpInputs = document.querySelectorAll('.fp-otp');
            let enteredCode = '';
            otpInputs.forEach(input => { enteredCode += input.value.trim(); });

            if (enteredCode.length < 6) {
                showAlertBox('Please enter the complete 6-digit verification code.');
                return;
            }

            const btn = event ? event.currentTarget : document.querySelector('#fp-step-2 .wizard-btn-next');
            const btnOriginal = btn ? btn.innerHTML : '';
            if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...'; }

            // Verified against the real hashed code + 10-minute expiry on
            // the server (AuthController::verifyOtp), not a value generated
            // and only ever compared client-side.
            apiRequest('/forgot-password/verify-otp', 'POST', { email: fpTargetEmail, code: enteredCode }).then(() => {
                fpVerifiedCode = enteredCode;
                goToFpStep(3);
            }).catch(err => {
                showAlertBox(err.message || 'Error: Invalid verification code. Please try again.');
            }).finally(() => {
                if (btn) { btn.disabled = false; btn.innerHTML = btnOriginal; }
            });
        }

        function validateFpResetPassword() {
            const p1 = document.getElementById('fpNewPassword').value;
            const p2 = document.getElementById('fpConfirmPassword').value;

            if (!p1 || !p2) {
                showAlertBox('Please fill in both password fields.');
                return;
            }
            const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
            if (!passwordRegex.test(p1)) {
                showAlertBox('Password must be at least 8 characters long and contain both numbers and symbols.');
                return;
            }
            if (p1 !== p2) {
                showAlertBox('Error: Passwords do not match!');
                return;
            }

            const btn = document.querySelector('#fp-step-3 .wizard-btn-next');
            if (btn) { btn.disabled = true; btn.textContent = 'Resetting...'; }

            // Actually resets the real password server-side (bcrypt hash),
            // re-checking the OTP is still valid and unconsumed — this used
            // to just overwrite systemUsers[idx].password locally, which
            // does nothing real since the server never even sends the
            // password field to the browser in the first place.
            apiRequest('/forgot-password/reset', 'POST', { email: fpTargetEmail, code: fpVerifiedCode, password: p1 }).then(() => {
                showAlertBox('Password successfully reset! You may now log in with your new password.');
                closeForgotPasswordModal();
            }).catch(err => {
                showAlertBox(err.message || 'Error: Could not reset the password. Please try again.');
            }).finally(() => {
                if (btn) { btn.disabled = false; btn.textContent = 'Reset Password'; }
            });
        }

        function goToSignupStep(stepNumber) {
            document.querySelectorAll('#signupModal .su-step').forEach(panel => {
                panel.classList.remove('active');
            });
            document.getElementById('su-step-' + stepNumber).classList.add('active');
            if (stepNumber === 5) {
                startSuSelfieCamera();
            }
        }

        function validateSuStep1() {
            const termsChecked = document.getElementById('suTermsConsent').checked;
            const privacyChecked = document.getElementById('suPrivacyConsent').checked;
            if (!termsChecked || !privacyChecked) {
                showAlertBox('Please check and agree to both the Terms and Conditions and Data Privacy Policy before proceeding.');
                return;
            }
            goToSignupStep(2);
        }

        function validateSuStep2() {
            const fullname = document.getElementById('suFullname').value.trim();
            const contact = document.getElementById('suContact').value.trim();
            const dob = document.getElementById('suDob').value;
            const gender = document.getElementById('suGender').value;
            if (!fullname || !contact || !dob || !gender) {
                showAlertBox('Please fill out all required fields before proceeding.');
                return;
            }
            suData.fullname = fullname;
            suData.contact = contact;
            suData.dob = dob;
            suData.gender = gender;
            suData.role = 'Staff';
            goToSignupStep(3);
        }

        function validateSuStep3() {
            const brgy = document.getElementById('suBrgy').value;
            if (!brgy) {
                showAlertBox('Please select your Barangay.');
                return;
            }
            suData.brgy = brgy;
            goToSignupStep(4);
        }

        // Shows "Uploading..." on the ID box the instant a photo is picked,
        // and only switches to the checkmark once it has actually finished
        // being read (same idea as a file-upload progress state here in
        // chat) -- large phone-camera photos can take a moment.
        function handleSuIdUpload(input, side) {
            if (input.files && input.files[0]) {
                const statusEl = document.getElementById(side === 'front' ? 'suIdFrontStatus' : 'suIdBackStatus');
                const box = statusEl ? statusEl.closest('.su-id-box') : null;
                if (statusEl) {
                    statusEl.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';
                    statusEl.style.color = 'var(--text-muted)';
                }
                if (box) box.style.pointerEvents = 'none';

                const reader = new FileReader();
                reader.onload = function(e) {
                    if (side === 'front') {
                        suData.frontId = e.target.result;
                    } else {
                        suData.backId = e.target.result;
                    }
                    if (statusEl) {
                        statusEl.textContent = (side === 'front' ? '✓ Front ID Captured' : '✓ Back ID Captured');
                        statusEl.style.color = 'var(--success-green)';
                    }
                    const prev = document.getElementById(side === 'front' ? 'suIdFrontPreview' : 'suIdBackPreview');
                    if (prev) { prev.src = e.target.result; prev.style.display = 'block'; }
                    if (box) box.style.pointerEvents = '';
                };
                reader.onerror = function() {
                    if (statusEl) {
                        statusEl.textContent = 'Upload failed — tap to try again';
                        statusEl.style.color = 'var(--primary-red)';
                    }
                    if (box) box.style.pointerEvents = '';
                };
                reader.readAsDataURL(input.files[0]);
            }
        }

        function validateSuStep4() {
            if (!suData.frontId || !suData.backId) {
                showAlertBox('Please capture or upload both the Front and Back of your ID before proceeding.');
                return;
            }
            goToSignupStep(5);
        }

        async function startSuSelfieCamera() {
            suSelfieCaptured = false;
            const video = document.getElementById('suSelfieVideo');
            const preview = document.getElementById('suSelfiePreview');
            const actionBtn = document.getElementById('suSelfieActionBtn');
            const retakeBtn = document.getElementById('suRetakeBtn');
            const instruction = document.getElementById('suSelfieInstruction');

            video.style.display = 'block';
            preview.style.display = 'none';
            actionBtn.textContent = 'Capture Photo';
            actionBtn.disabled = true;
            retakeBtn.style.display = 'none';
            // Opening the camera (and the browser's own permission prompt)
            // can take a moment on first use -- show that plainly instead of
            // a blank video box with no explanation.
            instruction.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Opening camera...';

            try {
                suSelfieStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' }, audio: false });
                video.srcObject = suSelfieStream;
                instruction.textContent = 'Hold phone still, look forward.';
            } catch (err) {
                console.warn('Front camera access unavailable:', err);
                instruction.textContent = 'Camera unavailable. You may skip this step.';
            } finally {
                actionBtn.disabled = false;
            }
        }

        function stopSuSelfieCamera() {
            if (suSelfieStream) {
                suSelfieStream.getTracks().forEach(track => track.stop());
                suSelfieStream = null;
            }
        }

        function captureSuSelfie() {
            if (!suSelfieCaptured) {
                const video = document.getElementById('suSelfieVideo');
                const canvas = document.getElementById('suSelfieCanvas');
                const preview = document.getElementById('suSelfiePreview');
                const retakeBtn = document.getElementById('suRetakeBtn');
                const actionBtn = document.getElementById('suSelfieActionBtn');
                const instruction = document.getElementById('suSelfieInstruction');

                canvas.width = video.videoWidth || 300;
                canvas.height = video.videoHeight || 300;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

                const dataUrl = canvas.toDataURL('image/png');
                preview.src = dataUrl;
                suData.faceDoc = dataUrl;
                video.style.display = 'none';
                preview.style.display = 'block';

                stopSuSelfieCamera();

                suSelfieCaptured = true;
                instruction.textContent = 'Review your photo. Retake if blur.';
                actionBtn.textContent = 'Proceed';
                retakeBtn.style.display = 'block';
            } else {
                goToSignupStep(6);
            }
        }

        function retakeSuSelfie() {
            startSuSelfieCamera();
        }

        function validateSuStep6() {
            const email = document.getElementById('suEmail').value.trim().toLowerCase();
            const p1 = document.getElementById('suPassword').value;
            const p2 = document.getElementById('suConfirmPassword').value;

            if (!email || !p1 || !p2) {
                showAlertBox('Please complete all fields.');
                return;
            }

            const exists = systemUsers.find(u => u.email.toLowerCase() === email);
            if (exists) {
                showAlertBox('This email already has a registered account.');
                return;
            }

            const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
            if (!passwordRegex.test(p1)) {
                showAlertBox('Password must be at least 8 characters long and contain both numbers and symbols.');
                return;
            }
            if (p1 !== p2) {
                showAlertBox('Passwords do not match!');
                return;
            }

            suData.email = email;
            suData.password = p1;

            document.getElementById('suSummaryFullname').value = suData.fullname || '';
            document.getElementById('suSummaryContact').value = suData.contact || '';
            document.getElementById('suSummaryGender').value = suData.gender || '';
            document.getElementById('suSummaryRole').value = suData.role || 'Staff';
            document.getElementById('suSummaryDob').value = suData.dob || '';
            document.getElementById('suSummaryBrgy').value = suData.brgy || '';
            document.getElementById('suSummaryEmail').value = suData.email || '';
            document.getElementById('suSummaryAvatar').src = suData.faceDoc || 'picture.jpg';

            goToSignupStep(7);
        }

        function confirmSuSignup() {
            const fullname = document.getElementById('suSummaryFullname').value.trim();
            const contact = document.getElementById('suSummaryContact').value.trim();
            const gender = document.getElementById('suSummaryGender').value.trim();
            const dob = document.getElementById('suSummaryDob').value.trim();
            const brgy = document.getElementById('suSummaryBrgy').value.trim();
            const email = document.getElementById('suSummaryEmail').value.trim().toLowerCase();

            if (!fullname || !contact || !email || !brgy) {
                showAlertBox('Please make sure Full Name, Contact Number, Barangay, and Email Address are filled out.');
                return;
            }

            const submitBtn = document.getElementById('suSubmitApprovalBtn');
            if (submitBtn) { submitBtn.disabled = true; submitBtn.innerText = 'Submitting...'; }

            // Actually submits to the real database — the previous version
            // of this function only ever pushed a fake 'staff_<timestamp>'
            // id into localStorage, so a Staff sign-up never reached the
            // server at all: Admin's Approval Verification page (on any
            // other device/session) never saw it, because there was never
            // really anything in the database to see. A selfie/ID photo is
            // NOT required here — the backend already accepts idFront/
            // idBack/faceDoc as optional, so Submit works with or without one.
            apiRequest('/register', 'POST', {
                name: fullname,
                email: email,
                password: suData.password,
                contact: contact,
                brgy: brgy,
                gender: gender,
                dob: dob,
                idFront: suData.frontId || null,
                idBack: suData.backId || null,
                faceDoc: suData.faceDoc || null,
            }).then(data => {
                if (data && data.user) {
                    systemUsers.push(data.user);
                    localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                }
                goToSignupStep(8);
            }).catch(err => {
                showAlertBox(err.message || 'Could not submit your sign-up request. Please check your connection and try again.');
            }).finally(() => {
                if (submitBtn) { submitBtn.disabled = false; submitBtn.innerText = 'Submit for Approval'; }
            });
        }

        function renderStaffApprovalList() {
            const listContainer = document.getElementById('pendingStaffList');
            if(!listContainer) return;
            
            const pendingStaff = systemUsers.filter(u => u.role === 'Staff' && u.status === 'Pending');
            
            if(pendingStaff.length === 0) {
                listContainer.innerHTML = '<div style="text-align:center; padding:15px; color:var(--text-muted);">No pending staff approvals at this time.</div>';
                return;
            }

            listContainer.innerHTML = pendingStaff.map(staff => `
                <div style="background:var(--card-bg); border:1px solid var(--border-color); padding:12px; border-radius:8px; margin-bottom:10px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-weight:bold; color:var(--text-dark);">${esc(staff.name)}</div>
                        <div style="font-size:12px; color:var(--text-muted);">${esc(staff.email)} | ${esc(staff.contact)}</div>
                        <div style="font-size:11px; color:var(--primary-red); font-weight:bold;">Barangay: ${esc(staff.brgy)}</div>
                    </div>
                    <div>
                        <button onclick="approveStaff('${esc(staff.id)}')" style="background:var(--success-green); color:white; border:none; padding:6px 12px; border-radius:4px; font-weight:bold; cursor:pointer; margin-right:5px;"><i class="fa-solid fa-check"></i> Approve</button>
                        <button onclick="rejectStaff('${esc(staff.id)}')" style="background:var(--primary-red); color:white; border:none; padding:6px 12px; border-radius:4px; font-weight:bold; cursor:pointer;"><i class="fa-solid fa-xmark"></i> Reject</button>
                    </div>
                </div>
            `).join('');
        }

        function approveStaff(staffId, event) {
            const idx = systemUsers.findIndex(u => u.id === staffId);
            if(idx !== -1) {
                const staffName = systemUsers[idx].name;
                const btn = event ? event.currentTarget : null;
                const btnOriginal = btn ? btn.innerHTML : '';
                if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Approving...'; }

                // Real server-side approval: flips the account's status to
                // Approved in the database (this is what actually lets the
                // Staff account log in — approveStaff() used to only ever
                // write to this browser's own localStorage, so the request
                // still showed "Pending" for every other Admin/device, and
                // the staff member still couldn't log in at all).
                apiRequest('/admin/staff/' + staffId + '/approve', 'PATCH').then(data => {
                    if (data && data.user) {
                        const freshIdx = systemUsers.findIndex(u => u.id === staffId);
                        if (freshIdx !== -1) systemUsers[freshIdx] = data.user;
                        localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                    }
                    // The server (StaffApprovalController::approve) already
                    // creates the real notification for the staff account —
                    // no separate local pushNotification() call here, so the
                    // staff member doesn't end up with a duplicate.
                    showAlertBox(`${staffName} has been approved as Staff! They can now log in.`);
                    renderUsersLogView();
                    renderAdminApprovalPageView();
                    renderStaffApprovalList();
                    updateStatisticsData();
                }).catch(err => {
                    if (btn) { btn.disabled = false; btn.style.opacity = '1'; btn.innerHTML = btnOriginal; }
                    showAlertBox(err.message || 'Error: Could not approve this staff account. Please try again.');
                });
            }
        }

        function rejectStaff(staffId, event) {
            const btn = event ? event.currentTarget : null;
            const btnOriginal = btn ? btn.innerHTML : '';
            showConfirmBox('Are you sure you want to reject this staff sign-up request?', () => {
                if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Rejecting...'; }
                // Real server-side rejection: actually deletes the pending
                // account from the database (previously local-only, so the
                // "rejected" request kept reappearing for every other
                // Admin/device and the account still existed).
                apiRequest('/admin/staff/' + staffId + '/reject', 'DELETE').then(() => {
                    systemUsers = systemUsers.filter(u => u.id !== staffId);
                    localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                    showAlertBox('The staff sign-up request has been rejected.');
                    renderUsersLogView();
                    renderAdminApprovalPageView();
                    renderStaffApprovalList();
                    updateStatisticsData();
                }).catch(err => {
                    if (btn) { btn.disabled = false; btn.style.opacity = '1'; btn.innerHTML = btnOriginal; }
                    showAlertBox(err.message || 'Error: Could not reject this staff account. Please try again.');
                });
            }, 'Reject Staff Sign-up');
        }

        // SINGLE SOURCE OF TRUTH FOR SIDEBAR STATE (prevents "closed" and "open"
        // classes from ever getting out of sync, so the menu always ends up
        // fully open or fully closed - no leftover sliver, just like Gmail).
        let isSidebarOpen = window.innerWidth > 768;

        function applySidebarState() {
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('main-content');
            if (!sidebar) return;
            sidebar.style.transform = '';
            if (isSidebarOpen) {
                sidebar.classList.add('open');
                sidebar.classList.remove('closed');
                if (mainContent) mainContent.classList.remove('expanded');
            } else {
                sidebar.classList.remove('open');
                sidebar.classList.add('closed');
                // On desktop the sidebar takes up space via margin-left on
                // main-content, so main-content must also collapse back or
                // a "leftover" gap is left behind where the sidebar used to be.
                if (mainContent) mainContent.classList.add('expanded');
            }
        }

        function toggleSidebar() {
            isSidebarOpen = !isSidebarOpen;
            applySidebarState();
        }

        // GMAIL-STYLE SWIPE TO CLOSE SIDEBAR MENU
        (function setupSidebarSwipeGesture() {
            const sidebar = document.getElementById('sidebar');
            if (!sidebar) return;
            const sidebarWidth = 280;
            let touchStartX = 0;
            let touchCurrentX = 0;
            let isDraggingSidebar = false;

            sidebar.addEventListener('touchstart', (e) => {
                if (!isSidebarOpen) return;
                touchStartX = e.touches[0].clientX;
                touchCurrentX = touchStartX;
                isDraggingSidebar = true;
                sidebar.style.transition = 'none';
            }, { passive: true });

            sidebar.addEventListener('touchmove', (e) => {
                if (!isDraggingSidebar) return;
                touchCurrentX = e.touches[0].clientX;
                const deltaX = touchCurrentX - touchStartX;
                if (deltaX < 0) {
                    sidebar.style.transform = `translateX(${deltaX}px)`;
                }
            }, { passive: true });

            sidebar.addEventListener('touchend', () => {
                if (!isDraggingSidebar) return;
                isDraggingSidebar = false;
                sidebar.style.transition = '';
                const deltaX = touchCurrentX - touchStartX;
                touchStartX = 0;
                touchCurrentX = 0;
                if (deltaX < -(sidebarWidth * 0.3)) {
                    // Swipe passed the threshold - close it completely, no residue.
                    isSidebarOpen = false;
                }
                applySidebarState();
            });
        })();

        function toggleDarkMode() {
            document.body.classList.toggle('dark-mode');
        }

        function toggleDropdown(id) {
            const drop = document.getElementById(id);
            drop.style.display = (drop.style.display === 'block') ? 'none' : 'block';
        }

        function switchMainPage(pageName, navBtnElement) {
            const pages = document.querySelectorAll('.page-view');
            pages.forEach(p => p.classList.remove('active'));

            const target = document.getElementById(`page-${pageName}`);
            if (target) target.classList.add('active');

            if (navBtnElement) {
                if (navBtnElement.classList.contains('side-custom-btn')) {
                    const sideItems = document.querySelectorAll('.side-custom-btn');
                    sideItems.forEach(n => n.classList.remove('active'));
                    navBtnElement.classList.add('active');
                } else {
                    const navItems = document.querySelectorAll('.bottom-nav-item');
                    navItems.forEach(n => n.classList.remove('active'));
                    navBtnElement.classList.add('active');
                }
            }

            // On mobile, tapping any bottom navigation item should always
            // close the sidebar menu completely (no leftover open sliver),
            // same behavior as swiping it closed.
            if (window.innerWidth <= 768 && isSidebarOpen) {
                isSidebarOpen = false;
                applySidebarState();
            }
        }

        // Switches between the "About Us" and "FAQ" sub-panels inside the
        // About page without affecting any other page/section.
        function loadSubModule(moduleName) {
            const aboutPanel = document.getElementById('aboutSubPanel');
            const faqPanel = document.getElementById('faqSubPanel');
            const aboutBtn = document.getElementById('aboutTabBtn');
            const faqBtn = document.getElementById('faqTabBtn');
            if (!aboutPanel || !faqPanel) return;

            if (moduleName === 'faq') {
                aboutPanel.classList.remove('active');
                faqPanel.classList.add('active');
                if (aboutBtn) aboutBtn.classList.remove('active');
                if (faqBtn) faqBtn.classList.add('active');
            } else {
                faqPanel.classList.remove('active');
                aboutPanel.classList.add('active');
                if (faqBtn) faqBtn.classList.remove('active');
                if (aboutBtn) aboutBtn.classList.add('active');
            }
        }

        // Expands/collapses a single FAQ question's answer, arrow rotates via CSS.
        function toggleFaqItem(buttonEl) {
            const item = buttonEl.closest('.faq-item');
            if (item) item.classList.toggle('open');
        }

        function handleProfileImageUpload(event) {
            const file = event.target.files[0];
            if (file) {
                const label = document.querySelector('.profile-photo-change-text');
                const labelOriginal = label ? label.innerHTML : '';
                if (label) label.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';

                const reader = new FileReader();
                reader.onload = function(e) {
                    document.getElementById('profileAvatarImg').src = e.target.result;
                    if (isViewingStaff) {
                        document.getElementById('headerAvatarImg').src = e.target.result;
                        staffData.avatar = e.target.result;
                        localStorage.setItem('redflow_staff_profile', JSON.stringify(staffData));
                    }
                    if (label) label.innerHTML = labelOriginal;
                    showAlertBox('Profile photo updated successfully!');
                };
                reader.onerror = function() {
                    if (label) label.innerHTML = labelOriginal;
                    showAlertBox('Error: That photo could not be uploaded. Please try a different file.');
                };
                reader.readAsDataURL(file);
            }
        }
function handleWizardAvatarUpload(event) {
            const file = event.target.files[0];
            if (file) {
                const label = document.getElementById('wizardAvatarUploadLabel');
                const labelOriginal = label ? label.innerHTML : '';
                if (label) label.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';

                const reader = new FileReader();
                reader.onload = function(e) {
                    document.getElementById('wizardAvatarPreview').src = e.target.result;
                    if (label) label.innerHTML = labelOriginal;
                };
                reader.onerror = function() {
                    if (label) label.innerHTML = labelOriginal;
                    showAlertBox('Error: That photo could not be uploaded. Please try a different file.');
                };
                reader.readAsDataURL(file);
            }
        }

        function handleSuAvatarUpload(event) {
            const file = event.target.files[0];
            if (file) {
                const label = document.getElementById('suAvatarUploadLabel');
                const labelOriginal = label ? label.innerHTML : '';
                if (label) label.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';

                const reader = new FileReader();
                reader.onload = function(e) {
                    document.getElementById('suSummaryAvatar').src = e.target.result;
                    suData.faceDoc = e.target.result;
                    if (label) label.innerHTML = labelOriginal;
                };
                reader.onerror = function() {
                    if (label) label.innerHTML = labelOriginal;
                    showAlertBox('Error: That photo could not be uploaded. Please try a different file.');
                };
                reader.readAsDataURL(file);
            }
        }

        // Inline SVG eye icons — intentionally NOT dependent on the
        // FontAwesome CDN (nor an emoji), so the show/hide toggle on
        // Login, Account Security, and Create Password always renders
        // correctly even if a CDN is blocked/offline.
        const EYE_ICON_SVG = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
        const EYE_SLASH_ICON_SVG = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.94 10.94 0 0112 20c-7 0-11-8-11-8a21.6 21.6 0 015.06-6.06M9.9 4.24A10.94 10.94 0 0112 4c7 0 11 8 11 8a21.6 21.6 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';

        function togglePasswordVisibility(fieldId, buttonElement) {
            const inputField = document.getElementById(fieldId);
            if (inputField.type === 'password') {
                inputField.type = 'text';
                buttonElement.innerHTML = EYE_SLASH_ICON_SVG;
            } else {
                inputField.type = 'password';
                buttonElement.innerHTML = EYE_ICON_SVG;
            }
        }

        function confirmLogout() {
            const btn = document.querySelector('#logoutModal .btn-confirm');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Logging out...';
            }
            // Actually destroys the server-side session too — without this,
            // the PHP session cookie would stay valid and a stale session
            // could keep hitting protected /api/* routes as this user.
            apiRequest('/logout', 'POST').catch(() => {}).finally(() => {
                closeModal('logoutModal');
                // PRIVACY: the donor list, records, audit log, notifications and
                // user list are copied into this browser while you work. Wipe
                // them at logout so the next person who uses this computer
                // (school lab, shared laptop) cannot read them from the
                // browser's storage. They are re-downloaded from the server
                // the next time someone logs in.
                wipeLocalAppData();
                document.getElementById('mainAppContainer').style.display = 'none';
                document.getElementById('loginView').classList.remove('hidden');
                showAlertBox('You have logged out.');
            });
        }

        // ============ CHANGE PASSWORD (email -> 6-digit code -> new password) ============
        let cpTargetEmail = '';
        let cpVerifiedCode = '';

        function goToCpStep(stepNumber) {
            document.querySelectorAll('#page-settings .cp-step').forEach(panel => panel.classList.remove('active'));
            const target = document.getElementById('cp-step-' + stepNumber);
            if (target) target.classList.add('active');
        }

        // Puts the Change Password card back to step 1 (email) with clean
        // fields. Called whenever Account Security is opened, on Cancel, and
        // after a successful change.
        function resetChangePasswordFlow() {
            cpTargetEmail = '';
            cpVerifiedCode = '';
            ['currentPassInput', 'newPassInput', 'confirmPassInput'].forEach(id => {
                const el = document.getElementById(id);
                if (el) { el.value = ''; el.type = 'password'; }
            });
            document.querySelectorAll('.cp-otp').forEach(input => input.value = '');
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            // Left empty on purpose: the person types their own email address.
            const emailInput = document.getElementById('cpEmailInput');
            if (emailInput) emailInput.value = '';
            const sendBtn = document.getElementById('cpSendCodeBtn');
            if (sendBtn) { sendBtn.textContent = 'Send Code'; sendBtn.disabled = false; sendBtn.style.opacity = '1'; }
            goToCpStep(1);
        }

        function cpSendCode() {
            const email = document.getElementById('cpEmailInput').value.trim().toLowerCase();
            if (!email) {
                showAlertBox('Error: Please enter your email address.');
                return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                showAlertBox('Error: Please enter a valid email address.');
                return;
            }
            if (!navigator.onLine) {
                showAlertBox(FP_EMAIL_FAIL_MSG);
                return;
            }

            const btn = document.getElementById('cpSendCodeBtn');
            btn.textContent = 'Sending...';
            btn.disabled = true;
            btn.style.opacity = '0.6';

            apiRequest('/change-password/send-otp', 'POST', { email: email }).then(() => {
                cpTargetEmail = email;
                document.getElementById('cpEmailTargetText').textContent = `Check ${email} for your 6-digit code.`;
                document.querySelectorAll('.cp-otp').forEach(input => input.value = '');
                goToCpStep(2);
                const first = document.querySelector('.cp-otp');
                if (first) first.focus();
            }).catch(err => {
                showAlertBox(err.isNetworkError ? FP_EMAIL_FAIL_MSG : (err.message || FP_EMAIL_FAIL_MSG));
            }).finally(() => {
                btn.textContent = 'Send Code';
                btn.disabled = false;
                btn.style.opacity = '1';
            });
        }

        function cpResendCode(btn) {
            resendOtpWithFeedback(btn, '/change-password/send-otp', cpTargetEmail,
                `A new verification code has been sent to ${cpTargetEmail}.`,
                () => goToCpStep(1));
        }

        function cpVerifyCode(event) {
            let enteredCode = '';
            document.querySelectorAll('.cp-otp').forEach(input => { enteredCode += input.value.trim(); });
            if (enteredCode.length < 6) {
                showAlertBox('Please enter the complete 6-digit verification code.');
                return;
            }
            const btn = event ? event.currentTarget : document.querySelector('#cp-step-2 .action-main-btn');
            const btnOriginal = btn ? btn.innerHTML : '';
            if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...'; }

            // Checked against the real hashed code + 10-minute expiry on the server.
            apiRequest('/change-password/verify-otp', 'POST', { email: cpTargetEmail, code: enteredCode }).then(() => {
                cpVerifiedCode = enteredCode;
                const shownEmail = document.getElementById('cpEmailShown');
                shownEmail.value = cpTargetEmail;
                // Editable: the person can keep this email or type a new one.
                shownEmail.removeAttribute('readonly');
                shownEmail.readOnly = false;
                shownEmail.disabled = false;
                goToCpStep(3);
            }).catch(err => {
                showAlertBox(err.message || 'Error: Invalid verification code. Please try again.');
            }).finally(() => {
                if (btn) { btn.disabled = false; btn.innerHTML = btnOriginal; }
            });
        }

        function validateAndChangePassword() {
            const currentPass = document.getElementById('currentPassInput').value;
            const newPass = document.getElementById('newPassInput').value;
            const confirmPass = document.getElementById('confirmPassInput').value;

            if (!cpTargetEmail || !cpVerifiedCode) {
                showAlertBox('Error: Please verify your email address with the 6-digit code first.');
                goToCpStep(1);
                return;
            }
            // The email field on this step can be edited: keeping it as-is
            // changes only the password; typing a different address ALSO
            // replaces the account's email with the new one.
            const emailFieldValue = document.getElementById('cpEmailShown').value.trim().toLowerCase();
            if (!emailFieldValue || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailFieldValue)) {
                showAlertBox('Error: Please enter a valid email address.');
                return;
            }
            if (!currentPass) {
                showAlertBox('Error: Please enter your current password.');
                return;
            }

            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
            if (!currentUser) {
                showAlertBox('Error: No logged in account found.');
                return;
            }

            // Current-password verification happens server-side against the
            // real bcrypt hash (see AuthController::changePassword).
            const hasLength = newPass.length >= 8;
            const hasNumber = /[0-9]/.test(newPass);
            const hasSymbol = /[^A-Za-z0-9]/.test(newPass);
            if (!hasLength || !hasNumber || !hasSymbol) {
                showAlertBox('Error: Password must be at least 8 characters with numbers & symbols.');
                return;
            }
            if (newPass !== confirmPass) {
                showAlertBox('Error: New Password and Confirm New Password do not match.');
                return;
            }
            if (newPass === currentPass) {
                showAlertBox('Error: New Password must be different from your Current Password.');
                return;
            }

            const submitBtn = document.querySelector('#cp-step-3 button[type="submit"]');
            const submitBtnOriginal = submitBtn ? submitBtn.innerHTML : '';
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.style.opacity = '0.6';
                submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Updating Password...';
            }

            const payload = {
                email: cpTargetEmail,
                code: cpVerifiedCode,
                current_password: currentPass,
                password: newPass
            };
            const emailChanged = emailFieldValue !== cpTargetEmail;
            if (emailChanged) payload.new_email = emailFieldValue;

            apiRequest('/change-password', 'POST', payload).then(() => {
                if (emailChanged) {
                    const cu = JSON.parse(localStorage.getItem('redflow_current_user'));
                    if (cu) {
                        cu.email = emailFieldValue;
                        localStorage.setItem('redflow_current_user', JSON.stringify(cu));
                        const idx = systemUsers.findIndex(u => u.id === cu.id);
                        if (idx !== -1) {
                            systemUsers[idx].email = emailFieldValue;
                            localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                        }
                    }
                }
                showAlertBox(emailChanged ? 'Password and email address updated successfully!' : 'Password updated successfully!');
                resetChangePasswordFlow();
                refreshAuditLogFromServer();
            }).catch(err => {
                showAlertBox(err.isNetworkError ? 'Error: No internet connection. Please check your connection and try again.' : (err.message || 'Error: Current Password is incorrect.'));
            }).finally(() => {
                if (submitBtn) { submitBtn.disabled = false; submitBtn.style.opacity = '1'; submitBtn.innerHTML = submitBtnOriginal; }
            });
        }

        function openStaffProfile() {
            isViewingStaff = true;
            const currentUser = JSON.parse(localStorage.getItem('redflow_current_user')) || staffData;
            const container = document.getElementById('profile-container-box');
            // Fields start locked (disabled) — same as the Donor Profile. They
            // only become editable after pressing "Edit", and the Cancel /
            // Update buttons appear at that point.
            container.innerHTML = `
                <div class="profile-back-row"><button type="button" class="profile-back-btn" onclick="switchMainPage('home', document.querySelector('.bottom-nav-item'))"><i class="fa-solid fa-arrow-left"></i> Back</button></div>
                <h2>ACCOUNT INFORMATION</h2>
                
                <input type="file" id="profileImageFile" accept="image/*" style="display: none;" onchange="handleProfileImageUpload(event)">
                
                <div class="profile-avatar-large" onclick="document.getElementById('profileImageFile').click()" title="Click to change photo">
                    <img id="profileAvatarImg" src="${esc(staffData.avatar || 'picture.jpg')}" alt="Profile" onerror="this.onerror=null;this.src='picture.jpg'">
                </div>
                <div class="profile-photo-change-text" onclick="document.getElementById('profileImageFile').click()">
                    <i class="fa-solid fa-camera"></i> Click to change photo
                </div>
                
                <form onsubmit="event.preventDefault();">
                    <div class="form-group-custom">
                        <label>FULL NAME</label>
                        <input type="text" id="staff_name" value="${esc(currentUser.name || staffData.name)}" required disabled>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>ROLE</label>
                            <input type="text" id="staff_role" value="${esc(currentUser.role || staffData.role)}" readonly disabled>
                        </div>
                        <div class="form-group-custom">
                            <label>SEX</label>
                            <select id="staff_sex" disabled>
                                <option value="Male" ${staffData.sex === 'Male' ? 'selected' : ''}>Male</option>
                                <option value="Female" ${staffData.sex === 'Female' ? 'selected' : ''}>Female</option>
                                <option value="Other" ${staffData.sex === 'Other' ? 'selected' : ''}>Other</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group-custom">
                        <label>BIRTHDAY</label>
                        <input type="date" id="staff_bday" value="${esc(staffData.bday)}" required disabled>
                    </div>
                    <div class="form-group-custom">
                        <label>COMPLETE ADDRESS</label>
                        <input type="text" id="staff_address" value="${esc(staffData.address)}" required disabled>
                    </div>
                    <div class="form-group-custom">
                        <label>CONTACT NUMBER</label>
                        <input type="tel" id="staff_contact" value="${esc(staffData.contact || currentUser.contact || '')}" placeholder="+639xxxxxxxxx" disabled>
                    </div>

                    <div id="staffProfileViewButtons">
                        <button type="button" onclick="enterStaffProfileEditMode()" style="width: 100%; padding: 14px; background-color: #222; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 15px;"><i class="fa-solid fa-pen"></i> Edit</button>
                    </div>
                    <div id="staffProfileEditButtons" style="display:none; gap:12px; margin-top:15px;">
                        <button type="button" onclick="cancelStaffProfileEditMode()" style="flex:1; padding: 14px; background-color: var(--primary-red); color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer;">Cancel</button>
                        <button type="button" id="staffProfileUpdateBtn" onclick="updateStaffProfileData()" style="flex:1; padding: 14px; background-color: var(--success-green); color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer;">Update</button>
                    </div>
                </form>
            `;
            switchMainPage('profile', null);
        }

        function enterStaffProfileEditMode() {
            ['staff_name','staff_sex','staff_bday','staff_address','staff_contact'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.disabled = false;
            });
            const vb = document.getElementById('staffProfileViewButtons');
            const eb = document.getElementById('staffProfileEditButtons');
            if (vb) vb.style.display = 'none';
            if (eb) eb.style.display = 'flex';
        }

        // Cancel throws away anything typed and shows the saved details again.
        function cancelStaffProfileEditMode() {
            openStaffProfile();
        }

        function updateStaffProfileData() {
            const name = document.getElementById('staff_name').value.trim();
            const sex = document.getElementById('staff_sex').value;
            const bday = document.getElementById('staff_bday').value;
            const address = document.getElementById('staff_address').value.trim();
            const contact = document.getElementById('staff_contact').value.trim();

            if (!name) {
                showAlertBox('Error: Full Name is required.');
                return;
            }

            const btn = document.getElementById('staffProfileUpdateBtn');
            const btnOriginalHtml = btn ? btn.innerHTML : '';
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.6';
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Updating...';
            }

            // Saved to the database (this used to only update this browser's
            // local copy, so the changes were lost on another device).
            apiRequest('/api/profile', 'PUT', { name: name, sex: sex, bday: bday || null, address: address, contact: contact }).then(() => {
                staffData.name = name;
                staffData.sex = sex;
                staffData.bday = bday;
                staffData.address = address;
                staffData.contact = contact;
                localStorage.setItem('redflow_staff_profile', JSON.stringify(staffData));

                // KEEP THE LOGGED-IN USER'S RECORD (systemUsers + currentUser) IN SYNC
                const currentUser = JSON.parse(localStorage.getItem('redflow_current_user'));
                if (currentUser) {
                    currentUser.name = staffData.name;
                    currentUser.contact = staffData.contact;
                    localStorage.setItem('redflow_current_user', JSON.stringify(currentUser));
                    const userIdx = systemUsers.findIndex(u => u.id === currentUser.id);
                    if (userIdx !== -1) {
                        systemUsers[userIdx].name = staffData.name;
                        systemUsers[userIdx].contact = staffData.contact;
                        localStorage.setItem('redflow_system_users', JSON.stringify(systemUsers));
                    }
                }
                showAlertBox('Profile updated successfully!');
                openStaffProfile(); // back to the locked view with the saved details
            }).catch(err => {
                showAlertBox(err.message || 'Error: Could not update your profile. Please try again.');
                if (btn) { btn.disabled = false; btn.style.opacity = '1'; btn.innerHTML = btnOriginalHtml; }
            });
        }

        // ============ AUDIT TRAIL / SENSITIVE DATA ACCESS LOG (RA 10173 compliance) ============
        const AUDIT_LOG_MAX_ENTRIES = 500;
        function getCurrentUserForAudit() {
            const cu = JSON.parse(localStorage.getItem('redflow_current_user'));
            return cu || { id: 'unknown', name: 'Unknown User', role: 'Unknown' };
        }
        function logAuditEvent(action, donor, details) {
            if (!donor) return;
            const actingUser = getCurrentUserForAudit();
            const auditLog = JSON.parse(localStorage.getItem('redflow_audit_log')) || [];
            auditLog.unshift({
                id: Date.now() + '_' + Math.random().toString(36).slice(2, 8),
                timestamp: new Date().toISOString(),
                userId: actingUser.id,
                userName: actingUser.name,
                userRole: actingUser.role,
                action: action,
                donorId: donor.id,
                donorName: donor.name,
                details: details || ''
            });
            if (auditLog.length > AUDIT_LOG_MAX_ENTRIES) auditLog.length = AUDIT_LOG_MAX_ENTRIES;
            localStorage.setItem('redflow_audit_log', JSON.stringify(auditLog));
        }

        let selectedAuditLogIds = new Set();
        let currentRenderedAuditLogIds = [];

        // The five app-facing audit categories, each with its own fixed
        // badge color: Update=yellow, Create=green, Change=red, Export=
        // violet, Delete=blue.
        function auditActionBadgeColor(action) {
            if (action === 'Update') return { bg: '#ffc107', fg: '#222' };
            if (action === 'Create') return { bg: 'var(--success-green)', fg: '#fff' };
            if (action === 'Change') return { bg: 'var(--primary-red)', fg: '#fff' };
            if (action === 'Export') return { bg: '#6f42c1', fg: '#fff' };
            if (action === 'Delete') return { bg: '#1976d2', fg: '#fff' };
            return { bg: '#1976d2', fg: '#fff' }; // fallback for any unexpected action
        }

        // Pulls the latest Audit Log entries from the shared database and
        // re-renders. Called every time the Audit Log page is opened (not
        // just on login/page-load) so entries created by other staff/admin
        // accounts on other devices show up quickly instead of only after
        // the next full page refresh.
        function refreshAuditLogFromServer() {
            apiRequest('/api/audit-log').then(data => {
                if (data && data.entries) {
                    localStorage.setItem('redflow_audit_log', JSON.stringify(data.entries));
                    renderAuditLogView();
                }
            }).catch(() => { /* offline — keep showing the local cache */ });
        }

        function renderAuditLogView() {
            const container = document.getElementById('auditLogContainer');
            if (!container) return;
            const auditLog = JSON.parse(localStorage.getItem('redflow_audit_log')) || [];

            currentRenderedAuditLogIds = auditLog.map(entry => entry.id);
            selectedAuditLogIds.clear();
            refreshAuditLogDeleteBtn();
            const bulkBar = document.getElementById('auditLogBulkBar');
            if (bulkBar) bulkBar.style.display = 'flex';
            const selectAllBox = document.getElementById('auditLogSelectAll');
            if (selectAllBox) selectAllBox.checked = false;

            if (auditLog.length === 0) {
                container.innerHTML = '<p style="text-align:center; color:var(--text-muted); padding:20px;">No sensitive data access has been logged yet.</p>';
                return;
            }
            container.innerHTML = auditLog.map(entry => {
                const badge = auditActionBadgeColor(entry.action);
                return `
                <div style="background:var(--bg-light); border:1px solid var(--border-color); border-radius:8px; padding:12px 15px; display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; align-items:flex-start; gap:10px;">
                        <input type="checkbox" class="admin-row-checkbox" style="margin-top:4px;" onchange="toggleAuditLogSelect('${esc(entry.id)}', this.checked)">
                        <div>
                            <div style="font-weight:bold; color:var(--text-dark); font-size:14px;">${esc(entry.action)} — ${esc(entry.donorName || entry.userName)}</div>
                            <div style="font-size:12px; color:var(--text-muted);">By: ${esc(entry.userName)} (${esc(entry.userRole)}) &middot; ${formatLoginTimestamp(entry.timestamp)}</div>
                            ${entry.details ? `<div style="font-size:12px; color:var(--text-dark); margin-top:4px; background:var(--card-bg); border:1px solid var(--border-color); border-radius:6px; padding:6px 8px;"><strong>Changes:</strong> ${esc(entry.details)}</div>` : ''}
                        </div>
                    </div>
                    <span style="font-size:11px; font-weight:bold; padding:4px 10px; border-radius:12px; background:${badge.bg}; color:${badge.fg};">${esc(entry.action)}</span>
                </div>
            `;
            }).join('');
        }

        function toggleAuditLogSelect(id, checked) {
            if (checked) selectedAuditLogIds.add(id); else selectedAuditLogIds.delete(id);
            refreshAuditLogDeleteBtn();
        }

        function refreshAuditLogDeleteBtn() {
            const btn = document.getElementById('auditLogDeleteBtn');
            if (!btn) return;
            btn.innerHTML = `<i class="fa-solid fa-trash"></i> DELETE (${selectedAuditLogIds.size})`;
            btn.classList.toggle('active', selectedAuditLogIds.size > 0);
        }

        function toggleSelectAllAuditLog(checked) {
            document.querySelectorAll('#auditLogContainer .admin-row-checkbox').forEach(cb => cb.checked = checked);
            if (checked) currentRenderedAuditLogIds.forEach(id => selectedAuditLogIds.add(id));
            else selectedAuditLogIds.clear();
            refreshAuditLogDeleteBtn();
        }

        // Deleting audit records is serious, so it takes THREE separate
        // confirmation cards in a row. Pressing Cancel on any of them stops
        // everything; only after the third "Okay" does the delete happen.
        function showTripleConfirm(title, messages, onConfirm) {
            const step = (i) => {
                showConfirmBox(messages[i], () => {
                    if (i + 1 < messages.length) { step(i + 1); return; }
                    // Only the FINAL step's click needs to wait for the
                    // server -- returning the promise here is what makes
                    // that last confirm card show the loading spinner.
                    return onConfirm();
                }, title);
            };
            step(0);
        }

        function deleteSelectedAuditLogEntries() {
            if (selectedAuditLogIds.size === 0) return;
            const n = selectedAuditLogIds.size;
            const entryWord = n === 1 ? 'entry' : 'entries';
            showTripleConfirm('Delete Audit Log', [
                `You selected ${n} audit log ${entryWord} for deletion. Do you want to continue?`,
                `The selected ${entryWord} will be permanently removed. Do you still want to continue?`,
                'Final confirmation: this cannot be undone. Delete now?'
            ], () => {
                const idsToDelete = Array.from(selectedAuditLogIds);
                // Waits for the server to confirm the rows are actually gone
                // (the Okay button shows a spinner the whole time -- see
                // showConfirmBox) before touching the on-screen list at all.
                return apiRequest('/api/audit-log/bulk', 'DELETE', { ids: idsToDelete }).then(() => {
                    selectedAuditLogIds.clear();
                    refreshAuditLogFromServer();
                    showAlertBox('Selected audit log entries deleted successfully!');
                }).catch(err => {
                    showAlertBox(err.message || 'The delete did not reach the server (offline, or your session expired) — nothing was removed. Please try again.');
                });
            });
        }

        function clearAuditLog() {
            showTripleConfirm('Clear Audit Log', [
                'Do you want to clear the entire audit log?',
                'Every Create, Update, Delete, Export, and Change record will be permanently removed. Do you still want to continue?',
                'Final confirmation: this cannot be undone. Clear the audit log now?'
            ], () => {
                return apiRequest('/api/audit-log', 'DELETE').then(() => {
                    refreshAuditLogFromServer();
                    showAlertBox('Audit log cleared successfully!');
                }).catch(err => {
                    showAlertBox(err.message || 'The clear did not reach the server (offline, or your session expired) — nothing was removed. Please try again.');
                });
            });
        }

        // ============ EXPORT DONOR MASTERLIST — password first ============
        // Rules (enforced on the SERVER, see ExportController):
        //   * the account password must be entered before anything downloads;
        //   * 3 wrong passwords in a row -> 60-second wait;
        //   * only 3 exports within 24 hours.
        let exportLockTimer = null;

        function setExportModalMessage(text, kind) {
            const el = document.getElementById('exportModalMessage');
            if (!el) return;
            el.textContent = text || '';
            el.className = 'export-modal-message' + (kind ? ' ' + kind : '');
            el.style.display = text ? 'block' : 'none';
        }

        function formatWaitTime(totalSeconds) {
            const h = Math.floor(totalSeconds / 3600);
            const m = Math.floor((totalSeconds % 3600) / 60);
            const s = totalSeconds % 60;
            if (h > 0) return `${h} hour${h === 1 ? '' : 's'} ${m} minute${m === 1 ? '' : 's'}`;
            if (m > 0) return `${m} minute${m === 1 ? '' : 's'} ${s} second${s === 1 ? '' : 's'}`;
            return `${s} second${s === 1 ? '' : 's'}`;
        }

        // Counts down (the Export button stays disabled until it reaches 0).
        function startExportCountdown(seconds, messageFor, onDone) {
            clearInterval(exportLockTimer);
            const btn = document.getElementById('exportSubmitBtn');
            let left = seconds;
            btn.disabled = true;
            const tick = () => {
                if (left <= 0) {
                    clearInterval(exportLockTimer);
                    btn.disabled = false;
                    btn.textContent = 'Export';
                    if (onDone) onDone();
                    return;
                }
                btn.textContent = left > 3600 ? 'Locked' : `Wait ${left}s`;
                setExportModalMessage(messageFor(left), 'error');
                left--;
            };
            tick();
            exportLockTimer = setInterval(tick, 1000);
        }

        // The password box normally comes with the page's HTML. If a browser
        // (or the server) is still serving an OLDER copy of the page that does
        // not contain it, the Export button used to crash with
        // "Cannot set properties of null". This creates the box on the spot,
        // so Export works no matter which copy of the page is loaded.
        function ensureExportModal() {
            if (document.getElementById('exportPasswordModal')) return;
            const holder = document.createElement('div');
            holder.innerHTML = `
    <div class="modal-overlay" id="exportPasswordModal">
        <div class="modal-box export-modal-box">
            <h3>Export Donor Masterlist</h3>
            <p class="export-modal-text">For security, enter your account password to continue.</p>
            <div class="password-input-wrap export-password-wrap">
                <input type="password" id="exportPasswordInput" name="export-confirm-secret" placeholder="Enter your password" autocomplete="new-password" readonly onfocus="this.removeAttribute('readonly')" onkeydown="if(event.key==='Enter'){submitExportPassword();}">
                <button type="button" class="toggle-password" aria-label="Show or hide password" onclick="togglePasswordVisibility('exportPasswordInput', this)">${EYE_ICON_SVG}</button>
            </div>
            <div id="exportModalMessage" class="export-modal-message" style="display:none;"></div>
            <div class="modal-buttons">
                <button type="button" class="modal-btn btn-cancel" onclick="closeExportPasswordModal()">Cancel</button>
                <button type="button" class="modal-btn btn-confirm" id="exportSubmitBtn" onclick="submitExportPassword()">Export</button>
            </div>
        </div>
    </div>`;
            document.body.appendChild(holder.firstElementChild);
        }

        function openExportPasswordModal() {
            ensureExportModal();
            if (!donorsData || donorsData.length === 0) {
                showAlertBox('Cannot export: the Donor Masterlist is currently empty.');
                return;
            }
            clearInterval(exportLockTimer);
            const input = document.getElementById('exportPasswordInput');
            input.value = '';
            input.type = 'password';
            // Locked until the person clicks into it, so the browser's saved-password
            // autofill can't pre-fill it — the person must type the password.
            input.setAttribute('readonly', 'readonly');
            const eyeBtn = document.querySelector('#exportPasswordModal .toggle-password');
            if (eyeBtn) eyeBtn.innerHTML = EYE_ICON_SVG;
            const btn = document.getElementById('exportSubmitBtn');
            btn.disabled = false;
            btn.textContent = 'Export';
            setExportModalMessage('', '');
            openModal('exportPasswordModal');
            setTimeout(() => input.focus(), 60);
        }

        function closeExportPasswordModal() {
            clearInterval(exportLockTimer);
            document.getElementById('exportPasswordInput').value = '';
            closeModal('exportPasswordModal');
        }

        function submitExportPassword() {
            const btn = document.getElementById('exportSubmitBtn');
            if (btn.disabled) return;
            const input = document.getElementById('exportPasswordInput');
            const password = input.value;
            if (!password) {
                setExportModalMessage('Please enter your password.', 'error');
                return;
            }
            if (!navigator.onLine) {
                setExportModalMessage('No internet connection. Please check your connection and try again.', 'error');
                return;
            }
            btn.disabled = true;
            btn.textContent = 'Checking...';
            setExportModalMessage('', '');

            apiRequest('/admin/export/authorize', 'POST', { password }).then(res => {
                closeExportPasswordModal();
                exportDonorMasterlistCSV();
                const left = (res && typeof res.exports_left === 'number') ? res.exports_left : null;
                showAlertBox('Donor Masterlist exported successfully! Check your downloads folder.' +
                    (left !== null ? ` You have ${left} export${left === 1 ? '' : 's'} left in the next 24 hours.` : ''));
            }).catch(err => {
                btn.disabled = false;
                btn.textContent = 'Export';
                const d = err.data || {};
                input.value = '';
                if (err.status === 429 && d.code === 'quota') {
                    startExportCountdown(d.retry_after || 86400,
                        left => `Export limit reached. You can export again in ${formatWaitTime(left)}.`);
                } else if (err.status === 429) {
                    startExportCountdown(d.retry_after || 60,
                        left => `Too many incorrect password attempts. Please wait ${left} second${left === 1 ? '' : 's'} before trying again.`,
                        () => setExportModalMessage('You can enter your password again now.', 'info'));
                } else if (err.status === 422 && d.code === 'wrong') {
                    setExportModalMessage(`Incorrect password. ${d.attempts_left} attempt${d.attempts_left === 1 ? '' : 's'} left.`, 'error');
                    input.focus();
                } else if (err.isNetworkError) {
                    setExportModalMessage('No internet connection. Please check your connection and try again.', 'error');
                } else {
                    setExportModalMessage(err.message || 'Something went wrong. Please try again.', 'error');
                }
            });
        }

        // ============ EXPORT DONOR MASTERLIST (CSV — opens directly in Excel) ============
        // Only called AFTER the password + limits above have been approved.
        // ============ EXPORT DONOR MASTERLIST ============
        // Only called AFTER the password + limits above have been approved.
        //
        // Builds a REAL .xlsx workbook (via the SheetJS library loaded on the
        // page) instead of a plain .csv, so it opens already looking right in
        // Excel -- no manual work needed:
        //   - Every column is sized to fit its longest value (no "########").
        //   - Long digit strings (contact numbers, emergency contact numbers)
        //     are kept as TEXT, so Excel never turns a phone number into
        //     scientific notation like "1E+10".
        //   - The header row is bold with a light fill, and frozen so it
        //     stays visible while scrolling a long list.
        // If the SheetJS library could not load (no internet reaching the
        // CDN), this automatically falls back to the plain .csv it used to
        // produce, so Export still works either way.
        function exportDonorMasterlistCSV() {
            if (!donorsData || donorsData.length === 0) {
                showAlertBox('Cannot export: the Donor Masterlist is currently empty.');
                return;
            }
            // Medical Conditions is Admin-only everywhere else in the app,
            // so it's left out of the export entirely unless an Admin is
            // the one exporting (this button is Admin-only in the sidebar
            // already, but this check keeps it consistent even if called
            // directly).
            const includeMedical = isAdminUser();
            const headers = ['ID', 'Full Name', 'Blood Type', 'Barangay', 'Contact', 'Birthday', 'Last Donation', 'Times Donated', 'Weight (kg)', 'Eligibility Status', 'Allergies', ...(includeMedical ? ['Medical Conditions'] : []), 'Deferral/Screening Notes', 'Emergency Contact Name', 'Emergency Contact Number'];
            // Columns whose values must stay TEXT even though they look like
            // numbers (ID numbers, phone numbers) -- indices match `headers` above.
            const textColumns = new Set([0, 4, headers.length - 1]);
            const rowsRaw = donorsData.map(d => [
                d.id, d.name, d.bloodType, d.brgy, d.contact, d.bday, d.lastDonation, d.timesDonated,
                d.weight || 'N/A', d.eligibilityStatus || 'Eligible', d.allergies || 'None', ...(includeMedical ? [d.medicalConditions || 'None'] : []),
                d.deferralReason || '', d.emergencyContactName || '', d.emergencyContactNumber || ''
            ].map(v => (v === undefined || v === null ? '' : v)));
            const todayStr = new Date().toISOString().split('T')[0];
            const filenameBase = `REDFLOW_Donor_Masterlist_${todayStr}`;

            const finishExportLog = () => {
                // Exporting the full masterlist (including health fields) counts as
                // a bulk sensitive-data access, so it is logged too -- both
                // instantly (local, for immediate UI feedback) and to the shared
                // database (violet "Export" badge) so it shows up for every
                // Admin/device, not just this one.
                const actingUser = getCurrentUserForAudit();
                const auditLog = JSON.parse(localStorage.getItem('redflow_audit_log')) || [];
                auditLog.unshift({
                    id: Date.now() + '_' + Math.random().toString(36).slice(2, 8),
                    timestamp: new Date().toISOString(),
                    userId: actingUser.id,
                    userName: actingUser.name,
                    userRole: actingUser.role,
                    action: 'Export',
                    donorId: null,
                    donorName: `Full Masterlist (${donorsData.length} donors)`
                });
                if (auditLog.length > AUDIT_LOG_MAX_ENTRIES) auditLog.length = AUDIT_LOG_MAX_ENTRIES;
                localStorage.setItem('redflow_audit_log', JSON.stringify(auditLog));
                renderAuditLogView();
                // (The shared "Export" audit entry is written by the server when
                // the password is approved -- see ExportController.)
            };

            if (typeof XLSX !== 'undefined') {
                const ws = XLSX.utils.aoa_to_sheet([headers, ...rowsRaw]);

                // Force the text-only columns to stay text (prevents Excel
                // from re-interpreting a long phone number as a number).
                rowsRaw.forEach((row, r) => {
                    textColumns.forEach(c => {
                        const ref = XLSX.utils.encode_cell({ r: r + 1, c });
                        if (ws[ref]) { ws[ref].t = 's'; ws[ref].z = '@'; }
                    });
                });

                // Column width = length of the longest value in that column
                // (header included), clamped so one long note can't make the
                // whole sheet absurdly wide.
                ws['!cols'] = headers.map((h, c) => {
                    let max = String(h).length;
                    rowsRaw.forEach(row => { max = Math.max(max, String(row[c] ?? '').length); });
                    return { wch: Math.max(10, Math.min(max + 2, 42)) };
                });

                // Bold header row + light fill so it stands out.
                headers.forEach((h, c) => {
                    const ref = XLSX.utils.encode_cell({ r: 0, c });
                    if (ws[ref]) {
                        ws[ref].s = { font: { bold: true }, fill: { fgColor: { rgb: 'FFE9E9E9' } } };
                    }
                });
                // Freeze the header row so it stays visible while scrolling.
                ws['!freeze'] = { xSplit: 0, ySplit: 1 };

                const wb = XLSX.utils.book_new();
                XLSX.utils.book_append_sheet(wb, ws, 'Donor Masterlist');
                XLSX.writeFile(wb, `${filenameBase}.xlsx`);
                finishExportLog();
                return;
            }

            // Fallback: plain CSV (used only if the XLSX library didn't load).
            const escapeCsv = (val) => {
                const str = String(val === undefined || val === null ? '' : val);
                return /["\n,]/.test(str) ? '"' + str.replace(/"/g, '""') + '"' : str;
            };
            const csvContent = [headers.map(escapeCsv).join(','), ...rowsRaw.map(row => row.map(escapeCsv).join(','))].join('\n');
            const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `${filenameBase}.csv`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            finishExportLog();
        }

        let currentProfileDonorSnapshot = null;

        function openDonorProfile(donor) {
            isViewingStaff = false;
            activeSelectedDonorId = donor.id;
            currentProfileDonorSnapshot = donor;
            const middleNameValue = donor.middleName && donor.middleName.trim() !== "" ? donor.middleName : "N/A";
            const container = document.getElementById('profile-container-box');
            container.innerHTML = `
                <div class="profile-back-row"><button type="button" class="profile-back-btn" onclick="switchMainPage('home', document.querySelector('.bottom-nav-item'))"><i class="fa-solid fa-arrow-left"></i> Back</button></div>
                <h2>ACCOUNT INFORMATION</h2>
                ${donor.createdBy ? `<p style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:-8px; margin-bottom:12px;">Created by: ${esc(donor.createdBy)}</p>` : ''}
                
                <input type="file" id="profileImageFile" accept="image/*" style="display: none;" onchange="handleProfileImageUpload(event)">
                
                <div class="profile-avatar-large" onclick="document.getElementById('profileImageFile').click()" title="Click to change photo">
                    <img id="profileAvatarImg" src="${esc(donor.avatar || 'picture.jpg')}" alt="Profile" onerror="this.onerror=null;this.src='picture.jpg'">
                </div>
                <div class="profile-photo-change-text" onclick="document.getElementById('profileImageFile').click()">
                    <i class="fa-solid fa-camera"></i> Click to change photo
                </div>
                
                <form onsubmit="event.preventDefault();">
                    <input type="hidden" id="prof_donorId" value="${esc(donor.id)}">
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>FIRST NAME</label>
                            <input type="text" id="prof_firstName" value="${esc(donor.firstName || donor.name.split(' ')[0])}" required disabled>
                        </div>
                        <div class="form-group-custom">
                            <label>MIDDLE NAME</label>
                            <input type="text" id="prof_middleName" value="${esc(middleNameValue)}" disabled>
                        </div>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>SURNAME</label>
                            <input type="text" id="prof_surname" value="${esc(donor.surname || donor.name.split(' ').slice(1).join(' '))}" required disabled>
                        </div>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>EXT. NAME</label>
                            <select id="prof_ext" disabled>
                                <option value="" ${!donor.ext ? 'selected' : ''}>None</option>
                                <option value="Jr." ${donor.ext === 'Jr.' ? 'selected' : ''}>Jr.</option>
                                <option value="Sr." ${donor.ext === 'Sr.' ? 'selected' : ''}>Sr.</option>
                                <option value="II" ${donor.ext === 'II' ? 'selected' : ''}>II</option>
                                <option value="III" ${donor.ext === 'III' ? 'selected' : ''}>III</option>
                                <option value="IV" ${donor.ext === 'IV' ? 'selected' : ''}>IV</option>
                                <option value="V" ${donor.ext === 'V' ? 'selected' : ''}>V</option>
                            </select>
                        </div>
                        <div class="form-group-custom">
                            <label>BLOOD TYPE${(donor.bloodType && !isAdminUser()) ? ' <i class="fa-solid fa-lock" style="font-size:11px; color:var(--text-muted);" title="Only an Admin can edit Blood Type once it has been set"></i>' : ''}</label>
                            <select id="prof_bloodType" disabled data-lock="${(donor.bloodType && !isAdminUser()) ? '1' : '0'}">
                                ${(donor.bloodType && !['A+','A-','B+','B-','AB+','AB-','O+','O-'].includes(donor.bloodType)) ? `<option value="${esc(donor.bloodType)}" selected>${esc(donor.bloodType)}</option>` : ''}
                                <option value="A+" ${donor.bloodType === 'A+' ? 'selected' : ''}>A+</option>
                                <option value="A-" ${donor.bloodType === 'A-' ? 'selected' : ''}>A-</option>
                                <option value="B+" ${donor.bloodType === 'B+' ? 'selected' : ''}>B+</option>
                                <option value="B-" ${donor.bloodType === 'B-' ? 'selected' : ''}>B-</option>
                                <option value="AB+" ${donor.bloodType === 'AB+' ? 'selected' : ''}>AB+</option>
                                <option value="AB-" ${donor.bloodType === 'AB-' ? 'selected' : ''}>AB-</option>
                                <option value="O+" ${donor.bloodType === 'O+' ? 'selected' : ''}>O+</option>
                                <option value="O-" ${donor.bloodType === 'O-' ? 'selected' : ''}>O-</option>
                            </select>
                            ${(donor.bloodType && !isAdminUser()) ? '<div style="font-size:10px; color:var(--text-muted); margin-top:3px;">Locked — only an Admin can edit Blood Type once set.</div>' : ''}
                        </div>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>BIRTHDAY (DATE OF BIRTH)</label>
                            <input type="date" id="prof_bday" value="${esc(donor.bday || '')}" required disabled>
                        </div>
                        <div class="form-group-custom">
                            <label>SEX</label>
                            <select id="prof_sex" disabled>
                                ${(donor.sex !== 'Male' && donor.sex !== 'Female') ? `<option value="${esc(donor.sex || 'N/A')}" selected>${esc(donor.sex || 'N/A')}</option>` : ''}
                                <option value="Male" ${donor.sex === 'Male' ? 'selected' : ''}>Male</option>
                                <option value="Female" ${donor.sex === 'Female' ? 'selected' : ''}>Female</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>CONTACT NUMBER</label>
                            <input type="text" id="prof_contact" value="${esc(donor.contact || '')}" required disabled>
                        </div>
                        <div class="form-group-custom">
                            <label>LOCATION</label>
                            <input type="text" id="prof_location" value="${esc(donor.brgy)}, Irosin, Sorsogon, Bicol, Philippines" required disabled>
                        </div>
                    </div>
                    
                    <div style="margin-top:25px; margin-bottom:10px; border-top:1px solid var(--border-color); padding-top:15px;">
                        <div style="font-weight:bold; color:var(--primary-red); font-size:14px; letter-spacing:0.5px; text-transform:uppercase;">Health &amp; Additional Information</div>
                        <div style="font-size:11px; color:var(--text-muted); margin-top:3px;">For reference only. Final medical screening and eligibility must always be confirmed by authorized health personnel.</div>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>WEIGHT (KG)</label>
                            <input type="text" id="prof_weight" value="${esc(donor.weight && donor.weight !== 'N/A' ? donor.weight : '')}" placeholder="e.g. 60" disabled>
                        </div>
                        <div class="form-group-custom">
                            <label>DONATION ELIGIBILITY STATUS</label>
                            <select id="prof_eligibilityStatus" disabled>
                                <option value="Eligible" ${donor.eligibilityStatus === 'Eligible' || !donor.eligibilityStatus ? 'selected' : ''}>Eligible</option>
                                <option value="Deferred" ${donor.eligibilityStatus === 'Deferred' ? 'selected' : ''}>Deferred</option>
                                <option value="Under Review" ${donor.eligibilityStatus === 'Under Review' ? 'selected' : ''}>Under Review</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>KNOWN ALLERGIES</label>
                            <input type="text" id="prof_allergies" value="${esc(donor.allergies && donor.allergies !== 'None' ? donor.allergies : '')}" placeholder="None" disabled>
                        </div>
                        ${isAdminUser() ? `
                        <div class="form-group-custom">
                            <label>EXISTING MEDICAL CONDITIONS <span style="font-size:9px; color:var(--text-muted); text-transform:none;">(Admin only)</span></label>
                            <input type="text" id="prof_medicalConditions" value="${esc(donor.medicalConditions && donor.medicalConditions !== 'None' ? donor.medicalConditions : '')}" placeholder="None" disabled oninput="autoSuggestEligibilityFromMedicalCondition(this.value)">
                        </div>
                        ` : `
                        <input type="hidden" id="prof_medicalConditions" value="${esc(donor.medicalConditions || 'None')}">
                        `}
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom" style="flex:1 1 100%;">
                            <label>DEFERRAL / SCREENING NOTES</label>
                            <input type="text" id="prof_deferralReason" value="${esc(donor.deferralReason || '')}" placeholder="Reason if Deferred or Under Review" disabled>
                        </div>
                    </div>
                    <div class="form-row-dual">
                        <div class="form-group-custom">
                            <label>EMERGENCY CONTACT NAME</label>
                            <input type="text" id="prof_emergencyContactName" value="${esc(donor.emergencyContactName || '')}" placeholder="Full name" disabled>
                        </div>
                        <div class="form-group-custom">
                            <label>EMERGENCY CONTACT NUMBER</label>
                            <input type="text" id="prof_emergencyContactNumber" value="${esc(donor.emergencyContactNumber || '')}" placeholder="+639XXXXXXXXX" disabled>
                        </div>
                    </div>

                    <div id="donorProfileViewButtons">
                        <button type="button" onclick="enterDonorProfileEditMode()" style="width: 100%; padding: 14px; background-color: #222; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 15px;"><i class="fa-solid fa-pen"></i> Edit</button>
                    </div>
                    <div id="donorProfileEditButtons" style="display:none; gap:12px; margin-top:15px;">
                        <button type="button" onclick="cancelDonorProfileEditMode()" style="flex:1; padding: 14px; background-color: var(--primary-red); color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer;">Cancel</button>
                        <button type="button" id="donorProfileUpdateBtn" onclick="updateDonorProfileData()" style="flex:1; padding: 14px; background-color: var(--success-green); color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer;">Update</button>
                    </div>
                    
                    <button type="button" class="action-main-btn" onclick="openCreateHistoryForm()">Create History Record</button>
                </form>
            `;
            switchMainPage('profile', null);
        }

        // Auto-suggests Eligibility Status based on whether a medical
        // condition has been entered (Admin-only field): a non-empty
        // condition (e.g. HIV, or any disqualifying illness) suggests
        // Deferred; clearing it back to empty suggests Eligible again. The
        // Admin can still manually override the Eligibility Status select
        // afterward — this only auto-fills it, it doesn't lock it.
        function autoSuggestEligibilityFromMedicalCondition(value, targetFieldId = 'prof_eligibilityStatus') {
            const eligibilityField = document.getElementById(targetFieldId);
            if (!eligibilityField || eligibilityField.disabled) return;
            const trimmed = (value || '').trim();
            eligibilityField.value = (trimmed && trimmed.toLowerCase() !== 'none') ? 'Deferred' : 'Eligible';
        }

        function enterDonorProfileEditMode() {
            const ids = ['prof_firstName','prof_middleName','prof_surname','prof_ext','prof_bday','prof_sex',
                'prof_contact','prof_location','prof_weight','prof_eligibilityStatus','prof_allergies',
                'prof_medicalConditions','prof_deferralReason','prof_emergencyContactName','prof_emergencyContactNumber'];
            ids.forEach(id => { const el = document.getElementById(id); if (el) el.disabled = false; });
            const bt = document.getElementById('prof_bloodType');
            if (bt && bt.dataset.lock !== '1') bt.disabled = false;
            const vb = document.getElementById('donorProfileViewButtons');
            const eb = document.getElementById('donorProfileEditButtons');
            if (vb) vb.style.display = 'none';
            if (eb) eb.style.display = 'flex';
        }

        function cancelDonorProfileEditMode() {
            if (currentProfileDonorSnapshot) {
                openDonorProfile(currentProfileDonorSnapshot);
            }
        }

    function updateDonorProfileData() {
            const donorId = parseInt(document.getElementById('prof_donorId').value);
            const fName = document.getElementById('prof_firstName').value;
            let mName = document.getElementById('prof_middleName').value.trim();
            if (mName === "N/A" || mName === "") {
                mName = "";
            }
            const lName = document.getElementById('prof_surname').value;
            const ext = document.getElementById('prof_ext').value.trim();
            const sexField = document.getElementById('prof_sex');
            const sex = sexField ? sexField.value : '';
            const fullName = `${fName} ${mName ? mName + ' ' : ''}${lName}${ext ? ' ' + ext : ''}`;
            let bloodType = document.getElementById('prof_bloodType').value;
            const rawLoc = document.getElementById('prof_location').value;
            const brgyOnly = rawLoc.split(',')[0].trim();
            const contact = document.getElementById('prof_contact').value;
            const bday = document.getElementById('prof_bday').value;
            const avatar = document.getElementById('profileAvatarImg').src;

            const existingDonorRecord = donorsData.find(d => d.id === donorId);

            // NEW: BLOOD TYPE EDIT LOCK — once a Blood Type has been set by
            // staff, only an Admin may change it. Enforced here as well as in
            // the form (disabled field) in case of tampering.
            if (existingDonorRecord && existingDonorRecord.bloodType && !isAdminUser() && bloodType !== existingDonorRecord.bloodType) {
                bloodType = existingDonorRecord.bloodType;
                showAlertBox('Blood Type is locked and can only be changed by an Admin. The rest of the profile was updated.');
            }

            // finishProfileUpdate() holds everything that used to run after the
            // blood-type confirmation. Defined here as a closure so it can see
            // all the local variables above, and so it can be called either
            // immediately (no blood type change) or from inside the styled
            // confirm modal's Okay callback (blood type changed).
            function finishProfileUpdate() {
                const updateBtn = document.getElementById('donorProfileUpdateBtn');
                const updateBtnOriginalText = updateBtn ? updateBtn.innerHTML : '';
                if (updateBtn) {
                    updateBtn.disabled = true;
                    updateBtn.style.opacity = '0.7';
                    updateBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Updating...';
                }

                // Cross-check against this donor's own History Records for mismatches
                const mismatchedHistoryRecord = monitoringRecords.find(r => r.donorId && String(r.donorId) === String(donorId) && r.bloodType && r.bloodType !== bloodType);
                if (mismatchedHistoryRecord) {
                    showAlertBox(`Warning: A History Record on file for this donor shows blood type ${mismatchedHistoryRecord.bloodType}, which no longer matches ${bloodType}. Please verify before relying on this record.`);
                }

                // NEW: Health & Additional Information fields (additive, does not
                // touch any existing field above).
                const weightField = document.getElementById('prof_weight');
                const eligibilityField = document.getElementById('prof_eligibilityStatus');
                const allergiesField = document.getElementById('prof_allergies');
                const medicalConditionsField = document.getElementById('prof_medicalConditions');
                const deferralReasonField = document.getElementById('prof_deferralReason');
                const emergencyNameField = document.getElementById('prof_emergencyContactName');
                const emergencyNumberField = document.getElementById('prof_emergencyContactNumber');

                const weight = weightField && weightField.value.trim() !== '' ? weightField.value.trim() : 'N/A';
                const eligibilityStatus = eligibilityField ? eligibilityField.value : 'Eligible';
                const allergies = allergiesField && allergiesField.value.trim() !== '' ? allergiesField.value.trim() : 'None';
                const medicalConditions = medicalConditionsField && medicalConditionsField.value.trim() !== '' ? medicalConditionsField.value.trim() : 'None';
                const deferralReason = deferralReasonField ? deferralReasonField.value.trim() : '';
                const emergencyContactName = emergencyNameField ? emergencyNameField.value.trim() : '';
                const emergencyContactNumber = emergencyNumberField ? emergencyNumberField.value.trim() : '';

                const donorIndex = donorsData.findIndex(d => d.id === donorId);
                if (donorIndex !== -1) {
                    const beforeEdit = donorsData[donorIndex];
                    const afterEdit = {
                        ...beforeEdit,
                        name: fullName,
                        firstName: fName,
                        middleName: mName,
                        surname: lName,
                        ext: ext,
                        sex: sex,
                        bloodType: bloodType,
                        brgy: brgyOnly,
                        contact: contact,
                        bday: bday,
                        avatar: avatar,
                        weight: weight,
                        eligibilityStatus: eligibilityStatus,
                        allergies: allergies,
                        medicalConditions: medicalConditions,
                        deferralReason: deferralReason,
                        emergencyContactName: emergencyContactName,
                        emergencyContactNumber: emergencyContactNumber
                    };
                    // Tracks every individually-editable field, by name, so
                    // the Audit Log shows exactly what changed (e.g. "Ext:
                    // 'Jr.' -> 'Sr.'") instead of just a combined full-name
                    // diff that hides which specific part actually changed.
                    const trackedFields = {
                        firstName: 'First Name', middleName: 'Middle Name', surname: 'Surname',
                        ext: 'Ext.', sex: 'Sex/Gender', bloodType: 'Blood Type', brgy: 'Barangay',
                        contact: 'Contact Number', bday: 'Birthday', weight: 'Weight',
                        eligibilityStatus: 'Eligibility Status', allergies: 'Allergies',
                        medicalConditions: 'Medical Conditions', deferralReason: 'Deferral Notes',
                        emergencyContactName: 'Emergency Contact Name', emergencyContactNumber: 'Emergency Contact Number'
                    };
                    const changeDetails = Object.keys(trackedFields)
                        .filter(key => (beforeEdit[key] || '') !== (afterEdit[key] || ''))
                        .map(key => `${trackedFields[key]}: "${beforeEdit[key] || 'N/A'}" → "${afterEdit[key] || 'N/A'}"`);

                    donorsData[donorIndex] = afterEdit;
                    localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                    // Only log to the Audit Log when something actually
                    // changed — an "Update" click that changed nothing
                    // shouldn't clutter the log.
                    if (changeDetails.length > 0) {
                        logAuditEvent('Update', donorsData[donorIndex], changeDetails.join('; '));
                    }

                    // Keep this donor's History Record in sync with every field
                    // edited here (name, location, blood type), so the Record
                    // section never shows stale information after a profile update.
                    const recIndex = monitoringRecords.findIndex(r => (r.donorId && String(r.donorId) === String(donorId)) || (r.name && r.name.trim().toLowerCase() === (beforeEdit.name || '').trim().toLowerCase()));
                    if (recIndex !== -1) {
                        monitoringRecords[recIndex].donorId = donorId;
                        monitoringRecords[recIndex].name = fullName;
                        monitoringRecords[recIndex].location = `${brgyOnly}, Irosin, Sorsogon, Bicol, Philippines`;
                        monitoringRecords[recIndex].bloodType = bloodType;
                        localStorage.setItem('redflow_monitoring_records', JSON.stringify(monitoringRecords));
                        renderMonitoringTable();
                    }

                    currentProfileDonorSnapshot = afterEdit;

                    // Pushes the update to the shared database — PUT
                    // /api/donors/{id} — so this donor's info is current for
                    // every other Admin/Staff account on any device.
                    // _auditDetails carries the exact per-field diff computed
                    // above (e.g. "Barangay: "X" → "Y"") so the server logs
                    // specifically what changed instead of a generic "Donor
                    // profile updated." message.
                    //
                    // The "Updating..." state on the button now lasts for
                    // this whole save -- it only clears (and the profile view
                    // switches back to read-only) once the server has really
                    // confirmed the update, instead of flipping back
                    // instantly while the request is still in flight.
                    apiRequest('/api/donors/' + donorId, 'PUT', { ...afterEdit, _auditDetails: changeDetails.join('; ') }).then(() => {
                        if (recIndex !== -1) {
                            apiRequest('/api/donation-records', 'POST', monitoringRecords[recIndex]).catch(() => {});
                        }
                        renderDonorCards();
                        updateStatisticsData();
                        showAlertBox('Donor profile updated successfully!');
                        openDonorProfile(currentProfileDonorSnapshot);
                    }).catch(err => {
                        renderDonorCards();
                        updateStatisticsData();
                        showAlertBox(err.isNetworkError
                            ? 'No internet connection. The update was saved on this device only and will need to be re-applied once you are back online.'
                            : 'Warning: Could not save this update to the shared database. It is only saved on this device for now.');
                        openDonorProfile(currentProfileDonorSnapshot);
                    }).finally(() => {
                        if (updateBtn) {
                            updateBtn.disabled = false;
                            updateBtn.style.opacity = '1';
                            updateBtn.innerHTML = updateBtnOriginalText;
                        }
                    });
                } else {
                    if (updateBtn) {
                        updateBtn.disabled = false;
                        updateBtn.style.opacity = '1';
                        updateBtn.innerHTML = updateBtnOriginalText;
                    }
                }
            }

            // NEW: BLOOD TYPE CROSS-VALIDATION — a blood type change is a
            // critical edit, so require explicit confirmation before it is
            // allowed to overwrite the existing record (guards against typos).
            if (existingDonorRecord && existingDonorRecord.bloodType && existingDonorRecord.bloodType !== bloodType) {
                showConfirmBox(`Blood type change detected for ${fullName}: ${existingDonorRecord.bloodType} → ${bloodType}. This is a critical field. Confirm this is a verified correction and NOT a typo before proceeding.`, () => {
                    finishProfileUpdate();
                }, 'Confirm Blood Type Change');
                return;
            }

            finishProfileUpdate();
        }

        function openCreateHistoryForm() {
            const donorId = document.getElementById('prof_donorId') ? document.getElementById('prof_donorId').value : '';
            const donorRecord = donorsData.find(d => String(d.id) === String(donorId));
            const fName = document.getElementById('prof_firstName').value;
            const mName = document.getElementById('prof_middleName').value;
            const lName = document.getElementById('prof_surname').value;
            const validMName = (mName && mName !== "N/A") ? mName + ' ' : '';
            const fullName = `${fName} ${validMName}${lName}`;
            const bloodType = document.getElementById('prof_bloodType').value;
            const rawLoc = document.getElementById('prof_location').value;

            // SUGGEST THE NEXT DONATION COUNT BASED ON THE DONOR'S CURRENT RECORD
            const currentTimesDonated = donorRecord && donorRecord.timesDonated && donorRecord.timesDonated !== 'N/A' ? parseInt(donorRecord.timesDonated, 10) || 0 : 0;
            const suggestedTimesDonated = currentTimesDonated + 1;
            const todayStr = new Date().toISOString().split('T')[0];
            const priorLastDonation = donorRecord && donorRecord.lastDonation ? donorRecord.lastDonation : 'N/A';

            document.getElementById('history_form_donorId').value = donorId;
            document.getElementById('history_form_name').value = fullName;
            document.getElementById('history_form_location').value = rawLoc.includes('Irosin') ? rawLoc : `${rawLoc}, Irosin, Sorsogon, Bicol, Philippines`;
            document.getElementById('history_form_bloodType').value = bloodType;
            // NEW: Blood Type edit lock also applies here — only an Admin may
            // change it once it has already been set on the donor's record.
            document.getElementById('history_form_bloodType').disabled = !!(bloodType && !isAdminUser());
            document.getElementById('history_form_lastDonation').value = priorLastDonation;
            document.getElementById('history_form_newDonation').value = todayStr;
            document.getElementById('history_form_times').value = String(suggestedTimesDonated);
            document.getElementById('history_form_amount').value = "1 unit";
            document.getElementById('history_form_status').value = "Pending";
            updateHistoryStatusColor(document.getElementById('history_form_status'));
            switchMainPage('create-history-form', null);
        }

        function updateHistoryStatusColor(selectEl) {
            if (!selectEl) return;
            if (selectEl.value === 'Approved') {
                selectEl.style.background = 'var(--success-green)';
                selectEl.style.borderColor = 'var(--success-green)';
                selectEl.style.color = '#fff';
            } else {
                selectEl.style.background = 'var(--warning-orange)';
                selectEl.style.borderColor = 'var(--warning-orange)';
                selectEl.style.color = '#222';
            }
        }

        let isApprovingHistoryRecord = false;
        function approveAndCommitHistoryRecord(btn) {
            // Guard against a double-tap/slow-connection double submit, same
            // approach as Create Donor.
            if (isApprovingHistoryRecord) return;
            const actingUser = JSON.parse(localStorage.getItem('redflow_current_user') || 'null');
            const actingUserName = (actingUser && actingUser.name) ? actingUser.name : 'Unknown';
            const donorId = document.getElementById('history_form_donorId').value;
            const name = document.getElementById('history_form_name').value;
            const location = document.getElementById('history_form_location').value;
            let bloodType = document.getElementById('history_form_bloodType').value;
            // NEW: Blood Type edit lock — if a non-Admin somehow altered this
            // field, fall back to the donor's Blood Type of record.
            const donorForBloodTypeLock = donorsData.find(d => String(d.id) === String(donorId));
            if (donorForBloodTypeLock && donorForBloodTypeLock.bloodType && !isAdminUser() && bloodType !== donorForBloodTypeLock.bloodType) {
                bloodType = donorForBloodTypeLock.bloodType;
            }
            const priorLastDonation = document.getElementById('history_form_lastDonation').value;
            const newDonation = document.getElementById('history_form_newDonation').value;
            const timesDonated = document.getElementById('history_form_times').value.trim();
            const amount = document.getElementById('history_form_amount').value.trim();
            const status = document.getElementById('history_form_status').value;

            // VALIDATION: BLANK OR ZERO TIMES DONATED / AMOUNT MUST NOT BE APPROVED
            const timesDonatedNum = parseInt(timesDonated, 10);
            const amountNum = parseFloat(amount);
            if (!newDonation || timesDonated === '' || amount === '' || isNaN(timesDonatedNum) || timesDonatedNum <= 0 || isNaN(amountNum) || amountNum <= 0) {
                showAlertBox('Cannot proceed: New Donation date must be set, and Times Donated / Amount cannot be blank or zero.');
                return;
            }
            if (status !== 'Approved') {
                showAlertBox('Please select status as "Approved" to create and push record to history.');
                return;
            }

            isApprovingHistoryRecord = true;
            const btnOriginal = btn ? btn.innerHTML : '';
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.6';
                btn.style.cursor = 'not-allowed';
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Approving...';
            }
              // PREVENT DUPLICATE HISTORY ENTRIES: EACH DONOR MAY ONLY HAVE ONE
            // HISTORY RECORD. IF ONE ALREADY EXISTS (MATCHED BY DONOR ID, OR
            // BY NAME AS A FALLBACK), UPDATE IT IN PLACE AND APPEND THIS
            // DONATION TO ITS TRANSACTION LOG INSTEAD OF CREATING A NEW ROW.
            let existingIndex = monitoringRecords.findIndex(r => donorId && String(r.donorId) === String(donorId));
            if (existingIndex === -1) {
                existingIndex = monitoringRecords.findIndex(r => r.name.trim().toLowerCase() === name.trim().toLowerCase());
            }

            // NOTE: A brand-new "New Donation" is NOT yet a "Last Donation" -- it
            // only becomes part of the LAST DONATION TRANSACTION history once a
            // *subsequent* New Donation supersedes it. So we push the record's
            // PREVIOUS donation date (the one now being replaced) into the
            // transaction log -- never the just-entered New Donation itself.
            if (existingIndex !== -1) {
                const existingRecord = monitoringRecords[existingIndex];
                if (!Array.isArray(existingRecord.transactions)) existingRecord.transactions = [];
                const previousDonationDate = existingRecord.donationDate || priorLastDonation;
                if (previousDonationDate && previousDonationDate !== 'N/A') {
                    existingRecord.transactions.push({ date: previousDonationDate, timesDonated: existingRecord.timesDonated, amount: existingRecord.amount });
                }
                existingRecord.donorId = donorId || existingRecord.donorId || null;
                existingRecord.location = location;
                existingRecord.bloodType = bloodType;
                existingRecord.lastDonation = previousDonationDate;
                existingRecord.donationDate = newDonation;
                existingRecord.timesDonated = timesDonated;
                existingRecord.amount = amount;
                if (!existingRecord.createdBy) existingRecord.createdBy = actingUserName;
                existingRecord.lastEditedBy = actingUserName;
            } else {
                // First-ever history record for this donor: if they already had a
                // recorded Last Donation on the masterlist (but no history entry
                // yet), carry that one entry into the transaction log. Otherwise
                // the transaction log starts empty since there is no completed
                // Last Donation yet -- only this pending New Donation.
                const initialTransactions = [];
                if (priorLastDonation && priorLastDonation !== 'N/A') {
                    initialTransactions.push({ date: priorLastDonation, timesDonated: '', amount: '' });
                }
                const newRecord = {
                    id: Date.now(),
                    donorId: donorId || null,
                    name: name,
                    location: location,
                    bloodType: bloodType,
                    timesDonated: timesDonated,
                    donationDate: newDonation,
                    lastDonation: priorLastDonation,
                    amount: amount,
                    transactions: initialTransactions,
                    createdBy: actingUserName,
                    lastEditedBy: actingUserName
                };
                monitoringRecords.push(newRecord);
            }
            localStorage.setItem('redflow_monitoring_records', JSON.stringify(monitoringRecords));
            const savedRecord = existingIndex !== -1 ? monitoringRecords[existingIndex] : monitoringRecords[monitoringRecords.length - 1];

            // UPDATE THE DONOR'S MASTERLIST RECORD SO LAST DONATION & TIMES DONATED REFLECT THIS NEW RECORD
            let donorIndex = donorsData.findIndex(d => String(d.id) === String(donorId));
            if (donorIndex === -1) {
                donorIndex = donorsData.findIndex(d => d.name.trim().toLowerCase() === name.trim().toLowerCase());
            }
            if (donorIndex !== -1) {
                donorsData[donorIndex].lastDonation = newDonation;
                donorsData[donorIndex].timesDonated = timesDonated;
                localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                renderDonorCards();
                apiRequest('/api/donors/' + donorsData[donorIndex].id, 'PUT', donorsData[donorIndex]).catch(() => {});
            }

            renderMonitoringTable();
            updateStatisticsData();

            // The "Approving..." state on the button now lasts for the whole
            // save -- it only clears (and the page moves to History) once the
            // server has actually confirmed the record was saved, same as
            // Create Donor.
            const endApprovingState = () => {
                isApprovingHistoryRecord = false;
                if (btn) {
                    btn.disabled = false;
                    btn.style.opacity = '';
                    btn.style.cursor = '';
                    btn.innerHTML = btnOriginal;
                }
            };

            // Pushes this history record to the shared database (upsert:
            // creates or updates depending on whether it already has a real
            // server id) so every Admin/Staff account sees it, on any device.
            apiRequest('/api/donation-records', 'POST', savedRecord).then(data => {
                if (data && data.record) {
                    const idx = monitoringRecords.findIndex(r => r.id === savedRecord.id);
                    if (idx !== -1) {
                        monitoringRecords[idx] = data.record;
                        localStorage.setItem('redflow_monitoring_records', JSON.stringify(monitoringRecords));
                        renderMonitoringTable();
                    }
                }
                endApprovingState();
                showAlertBox('History record approved and created successfully!');
                switchMainPage('history', document.querySelectorAll('.bottom-nav-item')[2]);
            }).catch(err => {
                endApprovingState();
                showAlertBox(err.isNetworkError
                    ? 'No internet connection. The record was saved on this device only and will need to be re-added once you are back online.'
                    : 'Warning: Could not save this record to the shared database. It is only saved on this device for now.');
                switchMainPage('history', document.querySelectorAll('.bottom-nav-item')[2]);
            });
        }

        let selectedDonorIds = new Set();
        let currentRenderedDonorIds = [];

        function renderDonorCards(filteredList = null) {
            const wrapper = document.getElementById('donor-cards-wrapper');
            wrapper.innerHTML = '';
            const listToRender = filteredList || donorsData;
            const adminMode = isAdminUser();

            const countLabel = document.getElementById('donor-count-label');
            if (countLabel) {
                countLabel.innerText = `${listToRender.length} Donors List`;
            }

            currentRenderedDonorIds = listToRender.map(d => d.id);
            selectedDonorIds.clear();
            refreshDonorDeleteBtn();
            const bulkBar = document.getElementById('donorBulkBar');
            if (bulkBar) bulkBar.style.display = adminMode ? 'flex' : 'none';
            const selectAllBox = document.getElementById('donorSelectAll');
            if (selectAllBox) selectAllBox.checked = false;

            if (listToRender.length === 0) {
                wrapper.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">No donors found.</div>`;
                return;
            }
            listToRender.forEach(donor => {
                const card = document.createElement('div');
                card.className = 'donor-card-item';
                card.setAttribute('data-abo', donor.bloodType);
                card.setAttribute('data-brgy', donor.brgy);
                card.setAttribute('data-name', donor.name);
                const fullLocationText = `${donor.brgy}, Irosin, Sorsogon, Bicol, Philippines`;
                const lastDonationDate = donor.lastDonation || 'N/A';
                const timesDonatedCount = donor.timesDonated || '1';
                card.innerHTML = `
                    ${adminMode ? `<input type="checkbox" class="admin-row-checkbox" onchange="toggleDonorSelect(${esc(donor.id)}, this.checked)">` : ''}
                    <div class="donor-avatar-area">
                        <div class="avatar-circle">
                            <img src="${esc(donor.avatar || 'picture.jpg')}" alt="Donor" onerror="this.src='picture.jpg'">
                        </div>
                    </div>
                    <div class="donor-details-area">
                        <h4 class="donor-name-title">${esc(donor.name)}</h4>
                        <div class="donor-meta-tags">
                            <span class="badge-abo">${esc(donor.bloodType)}</span>
                            <span class="badge-brgy">${esc(fullLocationText)}</span>
                        </div>
                        <p class="last-donated-text">Last Donation: <strong>${esc(lastDonationDate)}</strong> | Times Donated: <strong>${esc(timesDonatedCount)}</strong></p>
                    </div>
                    <div class="donor-action-buttons">
                        <span class="eligibility-badge eligibility-${esc((donor.eligibilityStatus || 'Eligible').replace(/\s+/g, '-').toLowerCase())}">${esc(donor.eligibilityStatus || 'Eligible')}</span>
                        <a href="tel:${esc(donor.contact)}" class="action-btn-custom contact-btn"><i class="fa-solid fa-phone"></i> CALL</a>
                        <button class="action-btn-custom request-btn" onclick="openDonorProfile(${esc(JSON.stringify(donor))})">VIEW</button>
                    </div>
                `;
                wrapper.appendChild(card);
            });
        }

        function toggleDonorSelect(id, checked) {
            if (checked) selectedDonorIds.add(id); else selectedDonorIds.delete(id);
            refreshDonorDeleteBtn();
        }

        function refreshDonorDeleteBtn() {
            const btn = document.getElementById('donorDeleteBtn');
            if (!btn) return;
            btn.innerHTML = `<i class="fa-solid fa-trash"></i> DELETE (${selectedDonorIds.size})`;
            btn.classList.toggle('active', selectedDonorIds.size > 0);
        }

        function toggleSelectAllDonors(checked) {
            document.querySelectorAll('#donor-cards-wrapper .admin-row-checkbox').forEach(cb => cb.checked = checked);
            if (checked) currentRenderedDonorIds.forEach(id => selectedDonorIds.add(id));
            else selectedDonorIds.clear();
            refreshDonorDeleteBtn();
        }

        function deleteSelectedDonors() {
            if (selectedDonorIds.size === 0) return;
            showConfirmBox(`Are you sure you want to delete ${selectedDonorIds.size} selected donor(s)?`, () => {
                const idsToDelete = Array.from(selectedDonorIds);
                // Waits for the server to confirm the donors are actually
                // gone before removing them from the list on screen.
                return apiRequest('/api/donors', 'DELETE', { ids: idsToDelete }).then(() => {
                    donorsData = donorsData.filter(d => !selectedDonorIds.has(d.id));
                    localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                    selectedDonorIds.clear();
                    renderDonorCards();
                    updateStatisticsData();
                }).catch(err => {
                    showAlertBox(err.isNetworkError ? 'No internet connection. Please check your connection and try again.' : (err.message || 'Could not delete these donors from the database. Please try again.'));
                });
            }, 'Delete Donors');
        }

        let selectedRecordIds = new Set();
        let currentRenderedRecordIds = [];

        function renderMonitoringTable(filteredList = monitoringRecords) {
            const container = document.getElementById('monitoring-table-container');
            container.innerHTML = '';
            const adminMode = isAdminUser();

            currentRenderedRecordIds = filteredList.map(r => r.id);
            selectedRecordIds.clear();
            refreshHistoryDeleteBtn();
            const bulkBar = document.getElementById('historyBulkBar');
            if (bulkBar) bulkBar.style.display = adminMode ? 'flex' : 'none';
            const selectAllBox = document.getElementById('historySelectAll');
            if (selectAllBox) selectAllBox.checked = false;

            if (filteredList.length === 0) {
                container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">No records found.</div>`;
                return;
            }
            filteredList.forEach((record) => {
                const originalIndex = monitoringRecords.findIndex(r => r.id === record.id);
                const card = document.createElement('div');
                card.style.cssText = "background:var(--card-bg); border-radius:12px; padding:20px; box-shadow:0 2px 8px rgba(0,0,0,0.06); border:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center; cursor:pointer;";
                card.onclick = () => openRecordDetail(originalIndex);
                card.innerHTML = `
                    <div style="display:flex; align-items:center;">
                        ${adminMode ? `<input type="checkbox" class="admin-row-checkbox" onclick="event.stopPropagation();" onchange="toggleRecordSelect(${esc(record.id)}, this.checked)">` : ''}
                        <div>
                            <div style="font-size:18px; font-weight:bold; color:#111; margin-bottom:5px;">${esc(record.name)}</div>
                            <div style="font-size:14px; color:#555; margin-bottom:4px;">Times Donated: ${esc(record.timesDonated || '1')}</div>
                            <div style="font-size:14px; color:#555;">${esc(record.donationDate || '2026-08-18')}</div>
                        </div>
                    </div>
                    <div style="display:flex; align-items:center; gap:15px;">
                        <span style="background:var(--primary-red); color:white; padding:6px 14px; border-radius:6px; font-weight:bold; font-size:15px;">${esc(record.bloodType)}</span>
                        <i class="fa-solid fa-chevron-right" style="color:#aaa; font-size:18px;"></i>
                    </div>
                `;
                container.appendChild(card);
            });
        }
    function toggleRecordSelect(id, checked) {
            if (checked) selectedRecordIds.add(id); else selectedRecordIds.delete(id);
            refreshHistoryDeleteBtn();
        }

        function refreshHistoryDeleteBtn() {
            const btn = document.getElementById('historyDeleteBtn');
            if (!btn) return;
            btn.innerHTML = `<i class="fa-solid fa-trash"></i> DELETE (${selectedRecordIds.size})`;
            btn.classList.toggle('active', selectedRecordIds.size > 0);
        }

        function toggleSelectAllRecords(checked) {
            document.querySelectorAll('#monitoring-table-container .admin-row-checkbox').forEach(cb => cb.checked = checked);
            if (checked) currentRenderedRecordIds.forEach(id => selectedRecordIds.add(id));
            else selectedRecordIds.clear();
            refreshHistoryDeleteBtn();
        }

        function deleteSelectedRecords() {
            if (selectedRecordIds.size === 0) return;
            showConfirmBox(`Are you sure you want to delete ${selectedRecordIds.size} selected history record(s)?`, () => {
                const idsToDelete = Array.from(selectedRecordIds);
                return apiRequest('/api/donation-records', 'DELETE', { ids: idsToDelete }).then(() => {
                    monitoringRecords = monitoringRecords.filter(r => !selectedRecordIds.has(r.id));
                    localStorage.setItem('redflow_monitoring_records', JSON.stringify(monitoringRecords));
                    selectedRecordIds.clear();
                    renderMonitoringTable();
                    updateStatisticsData();
                }).catch(err => {
                    showAlertBox(err.isNetworkError ? 'No internet connection. Please check your connection and try again.' : (err.message || 'Could not delete these records from the database. Please try again.'));
                });
            }, 'Delete Records');
        }

        function filterHistoryRecords() {
            const query = document.getElementById('history-search-input').value.toLowerCase();
            const filtered = monitoringRecords.filter(rec => 
                rec.name.toLowerCase().includes(query) || rec.bloodType.toLowerCase().includes(query)
            );
            renderMonitoringTable(filtered);
        }
        const debouncedFilterHistoryRecords = debounce(filterHistoryRecords, 250);

        function formatDateLong(dateStr) {
            if (!dateStr || dateStr === 'N/A') return 'N/A';
            const d = new Date(dateStr + 'T00:00:00');
            if (isNaN(d.getTime())) return dateStr;
            return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        }

        let currentOpenRecordIndex = null;

        function openRecordDetail(index) {
            currentOpenRecordIndex = index;
            const rec = monitoringRecords[index];
            document.getElementById('detail_name').innerText = rec.name;
            document.getElementById('detail_location').innerText = rec.location || 'N/A';
            document.getElementById('detail_bloodType').innerText = rec.bloodType;
            document.getElementById('detail_newDonation').innerText = formatDateLong(rec.donationDate) || '2026-08-18';
            document.getElementById('detail_lastDonation').innerText = formatDateLong(rec.lastDonation) || 'N/A';
            document.getElementById('detail_timesDonated').innerText = rec.timesDonated || '1';
            document.getElementById('detail_amount').innerText = rec.amount || '1 unit';
            document.getElementById('detail_createdBy').innerText = rec.createdBy || 'Unknown';

            renderLastDonationTransactionList(rec);
            cancelRecordEditMode();
            switchMainPage('single-record', null);
        }

        function renderLastDonationTransactionList(rec) {
            const txContainer = document.getElementById('lastDonationTransactionList');
            if (!txContainer) return;
            const transactions = Array.isArray(rec.transactions) ? rec.transactions.slice().reverse() : [];
            if (transactions.length === 0) {
                txContainer.innerHTML = '<div style="text-align:center; padding:15px; color:var(--text-muted); font-size:14px;">No prior donation transactions yet.</div>';
            } else {
                txContainer.innerHTML = transactions.map(tx => `
                    <div style="display:flex; justify-content:space-between; align-items:center; padding:14px 0; border-bottom:1px solid var(--border-color);">
                        <div style="font-size:15px; color:var(--text-dark);"><span style="font-weight:bold;">Last Donation:</span> ${formatDateLong(tx.date)}</div>
                        <div style="font-size:13px; color:var(--text-muted);">${esc(tx.timesDonated || '')} time(s) &bull; ${esc(tx.amount || '')}</div>
                    </div>
                `).join('');
            }
        }

        // ===== EDIT RECORD (full CRUD on the Single Record Detail view) =====
        function enterRecordEditMode() {
            if (currentOpenRecordIndex === null) return;
            const rec = monitoringRecords[currentOpenRecordIndex];

            document.getElementById('detail_name_edit').value = rec.name || '';
            document.getElementById('detail_location_edit').value = rec.location || '';
            document.getElementById('detail_bloodType_edit').value = rec.bloodType || 'O+';
            document.getElementById('detail_newDonation_edit').value = rec.donationDate || '';
            document.getElementById('detail_lastDonation_edit').value = (rec.lastDonation && rec.lastDonation !== 'N/A') ? rec.lastDonation : '';
            document.getElementById('detail_timesDonated_edit').value = rec.timesDonated || '1';
            document.getElementById('detail_amount_edit').value = rec.amount || '1 unit';

            // Blood Type is locked once a donor record has one set — same
            // rule as the Donor Profile View: only an Admin may change it,
            // Staff cannot, here in Record editing either.
            const bloodTypeLocked = !!(rec.bloodType && !isAdminUser());
            const bloodTypeSelect = document.getElementById('detail_bloodType_edit');
            bloodTypeSelect.disabled = bloodTypeLocked;
            const bloodTypeLockNote = document.getElementById('detail_bloodType_lock_note');
            if (bloodTypeLockNote) bloodTypeLockNote.style.display = bloodTypeLocked ? 'block' : 'none';

            ['name','location','bloodType','newDonation','lastDonation','timesDonated','amount'].forEach(f => {
                document.getElementById('detail_' + f).style.display = 'none';
                document.getElementById('detail_' + f + '_edit').style.display = 'block';
            });
            document.getElementById('recordViewButtons').style.display = 'none';
            document.getElementById('recordEditButtons').style.display = 'flex';
        }

        function cancelRecordEditMode() {
            ['name','location','bloodType','newDonation','lastDonation','timesDonated','amount'].forEach(f => {
                const viewEl = document.getElementById('detail_' + f);
                const editEl = document.getElementById('detail_' + f + '_edit');
                if (viewEl) viewEl.style.display = 'block';
                if (editEl) editEl.style.display = 'none';
            });
            const bloodTypeLockNote = document.getElementById('detail_bloodType_lock_note');
            if (bloodTypeLockNote) bloodTypeLockNote.style.display = 'none';
            const vb = document.getElementById('recordViewButtons');
            const eb = document.getElementById('recordEditButtons');
            if (vb) vb.style.display = 'block';
            if (eb) eb.style.display = 'none';
        }

        function saveRecordEdit() {
            if (currentOpenRecordIndex === null) return;
            const saveBtn = document.getElementById('saveRecordEditBtn');
            const saveBtnOriginal = saveBtn ? saveBtn.innerHTML : '';
            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.style.opacity = '0.6';
                saveBtn.style.cursor = 'not-allowed';
                saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
            }
            const rec = monitoringRecords[currentOpenRecordIndex];

            const newName = document.getElementById('detail_name_edit').value.trim();
            const newLocation = document.getElementById('detail_location_edit').value.trim();
            let newBloodType = document.getElementById('detail_bloodType_edit').value;
            const newDonationDate = document.getElementById('detail_newDonation_edit').value;
            const newLastDonationDate = document.getElementById('detail_lastDonation_edit').value;
            const newTimesDonated = document.getElementById('detail_timesDonated_edit').value.trim();
            const newAmount = document.getElementById('detail_amount_edit').value.trim();

            // Enforced again here (not just the disabled attribute) so Blood
            // Type can't be changed by Staff even via devtools tampering —
            // only an Admin may change it once a record already has one set.
            if (rec.bloodType && !isAdminUser() && newBloodType !== rec.bloodType) {
                newBloodType = rec.bloodType;
            }

            if (!newName || !newTimesDonated || !newAmount) {
                showAlertBox('Cannot save: Name, Times Donated, and Amount cannot be blank.');
                return;
            }

            const oldName = rec.name;
            const oldLocation = rec.location;
            const oldBloodType = rec.bloodType;
            const oldTimesDonated = rec.timesDonated;
            const oldAmount = rec.amount;
            const oldLastDonation = rec.lastDonation;
            const oldDonationDate = rec.donationDate;
            rec.name = newName;
            rec.location = newLocation;
            rec.bloodType = newBloodType;
            rec.donationDate = newDonationDate;
            rec.timesDonated = newTimesDonated;
            rec.amount = newAmount;

            // If the Last Donation date was changed, keep the most recent
            // entry in the Last Donation Transaction list in sync with it.
            // IMPORTANT: an empty Last Donation field on save does NOT mean
            // "clear it" — it usually just means the user was only editing
            // New Donation and left this field alone. Wiping it to "N/A"
            // here was the actual bug behind "inedit ko New Donation,
            // nagbago pa rin ang Last Donation" — so an empty value now
            // leaves the existing Last Donation untouched instead.
            if (newLastDonationDate) {
                rec.lastDonation = newLastDonationDate;
                if (Array.isArray(rec.transactions) && rec.transactions.length > 0) {
                    rec.transactions[rec.transactions.length - 1].date = newLastDonationDate;
                } else {
                    rec.transactions = [{ date: newLastDonationDate, timesDonated: newTimesDonated, amount: newAmount }];
                }
            }
            // (else: rec.lastDonation stays whatever it already was)

            const actingUser = JSON.parse(localStorage.getItem('redflow_current_user') || 'null');
            rec.lastEditedBy = (actingUser && actingUser.name) ? actingUser.name : rec.lastEditedBy || 'Unknown';
            if (!rec.createdBy) rec.createdBy = rec.lastEditedBy;

            // Logs this Record edit to the Audit Log so an Admin can see
            // exactly what a Staff member changed on this record, on any
            // device — this was previously not logged at all here (only
            // Donor Profile edits and donor creation were).
            const recordChangeParts = [];
            if (oldName !== rec.name) recordChangeParts.push(`Name: "${oldName}" → "${rec.name}"`);
            if (oldLocation !== rec.location) recordChangeParts.push(`Location: "${oldLocation}" → "${rec.location}"`);
            if (oldBloodType !== rec.bloodType) recordChangeParts.push(`Blood Type: "${oldBloodType}" → "${rec.bloodType}"`);
            if (oldTimesDonated !== rec.timesDonated) recordChangeParts.push(`Times Donated: "${oldTimesDonated}" → "${rec.timesDonated}"`);
            if (oldAmount !== rec.amount) recordChangeParts.push(`Amount: "${oldAmount}" → "${rec.amount}"`);
            if (oldDonationDate !== rec.donationDate) recordChangeParts.push(`New Donation: "${oldDonationDate}" → "${rec.donationDate}"`);
            if (oldLastDonation !== rec.lastDonation) recordChangeParts.push(`Last Donation: "${oldLastDonation}" → "${rec.lastDonation}"`);
            // Only log to the Audit Log when a field actually changed —
            // saving the Record with nothing changed doesn't need an entry.
            if (recordChangeParts.length > 0) {
                logAuditEvent('Update', { id: rec.donorId || rec.id, name: rec.name }, recordChangeParts.join('; '));
            }

            localStorage.setItem('redflow_monitoring_records', JSON.stringify(monitoringRecords));

            // Keep the donor masterlist entry (name, location, blood type, last
            // donation, times donated) in sync with this record.
            if (rec.donorId) {
                const donorIndex = donorsData.findIndex(d => String(d.id) === String(rec.donorId));
                if (donorIndex !== -1) {
                    donorsData[donorIndex].name = newName;
                    donorsData[donorIndex].location = newLocation;
                    donorsData[donorIndex].bloodType = newBloodType;
                    donorsData[donorIndex].timesDonated = newTimesDonated;
                    if (newLastDonationDate) donorsData[donorIndex].lastDonation = newLastDonationDate;
                    localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                    renderDonorCards();
                }
            } else if (oldName) {
                const donorIndex = donorsData.findIndex(d => d.name.trim().toLowerCase() === oldName.trim().toLowerCase());
                if (donorIndex !== -1) {
                    donorsData[donorIndex].name = newName;
                    donorsData[donorIndex].location = newLocation;
                    donorsData[donorIndex].bloodType = newBloodType;
                    donorsData[donorIndex].timesDonated = newTimesDonated;
                    if (newLastDonationDate) donorsData[donorIndex].lastDonation = newLastDonationDate;
                    localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                    renderDonorCards();
                }
            }

            // Refresh the view with the saved values.
            document.getElementById('detail_name').innerText = rec.name;
            document.getElementById('detail_location').innerText = rec.location || 'N/A';
            document.getElementById('detail_bloodType').innerText = rec.bloodType;
            document.getElementById('detail_newDonation').innerText = formatDateLong(rec.donationDate);
            document.getElementById('detail_lastDonation').innerText = formatDateLong(rec.lastDonation);
            document.getElementById('detail_timesDonated').innerText = rec.timesDonated;
            document.getElementById('detail_amount').innerText = rec.amount;
            document.getElementById('detail_createdBy').innerText = rec.createdBy || 'Unknown';
            renderLastDonationTransactionList(rec);
            renderMonitoringTable();
            updateStatisticsData();

            const endSavingState = () => {
                if (saveBtn) {
                    saveBtn.disabled = false;
                    saveBtn.style.opacity = '';
                    saveBtn.style.cursor = '';
                    saveBtn.innerHTML = saveBtnOriginal;
                }
            };

            // The "Saving..." state on the button now lasts for the whole
            // save -- it (and the success message) only fire once the server
            // has actually confirmed the edit was saved, the same pattern
            // used for Create Donor and Approve History Record.
            //
            // Pushes this edit to the shared database so it's not just
            // saved on this device -- the same upsert endpoint used when
            // the record was first created. _auditDetails carries the
            // exact field(s) that changed (e.g. just "Last Donation: ..."
            // when only that field changed) so the Audit Log shows exactly
            // what happened instead of a generic "New Donation / Last
            // Donation" message every time, regardless of which one
            // actually changed.
            apiRequest('/api/donation-records', 'POST', { ...rec, _auditDetails: recordChangeParts.join('; ') }).then(data => {
                if (data && data.record) {
                    const idx = monitoringRecords.findIndex(r => r.id === rec.id);
                    if (idx !== -1) {
                        monitoringRecords[idx] = data.record;
                        localStorage.setItem('redflow_monitoring_records', JSON.stringify(monitoringRecords));
                    }
                }
                endSavingState();
                cancelRecordEditMode();
                showAlertBox('Record updated successfully!');
            }).catch(err => {
                endSavingState();
                cancelRecordEditMode();
                showAlertBox(err.isNetworkError
                    ? 'No internet connection. This edit was saved on this device only and will need to be re-saved once you are back online.'
                    : 'Warning: Could not save this edit to the shared database. It is only saved on this device for now.');
            });
            if (rec.donorId) {
                // BUG FIX: this used to send the Record's full display
                // location ("Gumapia, Irosin, Sorsogon, Bicol, Philippines")
                // straight into the donor's `brgy` field, which is only
                // ever supposed to hold the short barangay name ("Gumapia").
                // That silently corrupted the donor's brgy on every single
                // Record save (even ones that never touched location at
                // all) -- and the NEXT time anyone opened that donor's
                // Profile and saved it, the Profile form correctly
                // recomputes the clean short barangay, which then looked
                // like a false "Barangay changed" entry in the Audit Log
                // (this is exactly the extra/unwanted line Drax reported).
                const brgyOnlyForDonorSync = newLocation.split(',')[0].trim();
                apiRequest('/api/donors/' + rec.donorId, 'PUT', { name: rec.name, bloodType: rec.bloodType, brgy: brgyOnlyForDonorSync, lastDonation: rec.lastDonation, timesDonated: rec.timesDonated }).catch(() => {});
            }
        }
  
        function goToWizardStep(stepNum) {
            document.getElementById('wizard-step-0').style.display = 'none';
            document.getElementById('wizard-step-1').style.display = 'none';
            document.getElementById('wizard-step-2').style.display = 'none';
            document.getElementById('wizard-step-4').style.display = 'none';
            if (stepNum === 0) {
                document.getElementById('wizard-step-0').style.display = 'block';
            } else if (stepNum === 1) {
                document.getElementById('wizard-step-1').style.display = 'block';
            } else if (stepNum === 2) {
                document.getElementById('wizard-step-2').style.display = 'block';
            } else if (stepNum === 4) {
                document.getElementById('wizard-step-4').style.display = 'block';
                populateReviewStep();
            }
        }

        function validateStep1AndProceed() {
            const fName = document.getElementById('w_firstName').value.trim();
            const lName = document.getElementById('w_lastName').value.trim();
            const bday = document.getElementById('w_bday').value;
            const contact = document.getElementById('w_contact').value.trim();
            const bloodType = document.getElementById('w_bloodType').value;
            const role = document.getElementById('w_role').value;
            if (!fName || !lName || !bday || !contact || !bloodType || !role) {
                showAlertBox('Please complete all required fields.');
                return;
            }
            // NEW: Blood Type confirmation check — Blood Type is a critical
            // field, so require the user to explicitly confirm it is correct
            // before moving on. Uses the same styled confirmation card as
            // the Logout modal instead of the plain browser confirm().
            document.getElementById('bloodTypeConfirmMessage').innerText = `You entered Blood Type: ${bloodType}. Are you sure this is correct?`;
            openModal('bloodTypeConfirmModal');
        }

        function confirmBloodTypeAndProceed() {
            closeModal('bloodTypeConfirmModal');
            goToWizardStep(2);
        }

        function validateStep2AndProceed() {
            const barangay = document.getElementById('w_barangay').value;
            if (!barangay) {
                showAlertBox('Please select your Barangay.');
                return;
            }
            goToWizardStep(4);
        }

        function toggleMiddleName(checkbox) {
            const middleInput = document.getElementById('w_middleName');
            if (checkbox.checked) {
                middleInput.value = '';
                middleInput.disabled = true;
            } else {
                middleInput.value = '';
                middleInput.disabled = false;
            }
        }

        function populateReviewStep() {
            document.getElementById('rev_firstName').value = document.getElementById('w_firstName').value;
            document.getElementById('rev_middleName').value = document.getElementById('w_middleName').value;
            document.getElementById('rev_lastName').value = document.getElementById('w_lastName').value;
            document.getElementById('rev_ext').value = document.getElementById('w_ext').value;
            document.getElementById('rev_bloodType').value = document.getElementById('w_bloodType').value;
            document.getElementById('rev_bday').value = document.getElementById('w_bday').value;
            document.getElementById('rev_contact').value = document.getElementById('w_contact').value;
            document.getElementById('rev_location').value = document.getElementById('w_barangay').value;
        }

        let isCreatingDonor = false;

        function commitNewDonor() {
            // Guard against duplicate donors from a double-tap or slow
            // connection: ignore repeat clicks while a creation is in flight.
            if (isCreatingDonor) return;
            isCreatingDonor = true;
            const createBtn = document.querySelector('#wizard-step-4 .action-main-btn');
            const createBtnOriginalText = createBtn ? createBtn.innerHTML : '';
            if (createBtn) {
                createBtn.disabled = true;
                createBtn.style.opacity = '0.6';
                createBtn.style.cursor = 'not-allowed';
                createBtn.innerHTML = 'Creating...';
            }

            const fName = document.getElementById('rev_firstName').value;
            let mName = document.getElementById('rev_middleName').value.trim();
            if (mName === "N/A") mName = "";
            const lName = document.getElementById('rev_lastName').value;
            const ext = document.getElementById('rev_ext').value.trim();
            const validMName = mName ? mName + ' ' : '';
            const validExt = ext ? ' ' + ext : '';
            const fullName = `${fName} ${validMName}${lName}${validExt}`;
            const bloodType = document.getElementById('rev_bloodType').value;
            const brgy = document.getElementById('rev_location').value;
            const contact = document.getElementById('rev_contact').value;
            const bday = document.getElementById('rev_bday').value;
            const avatarSrc = document.getElementById('wizardAvatarPreview').src || 'picture.jpg';
            const newDonorId = donorsData.length + 1;

            // NEW: read Health & Additional Information from wizard step 2 (falls
            // back to safe defaults if a field is left blank).
            const wWeightField = document.getElementById('w_weight');
            const wEligibilityField = document.getElementById('w_eligibilityStatus');
            const wAllergiesField = document.getElementById('w_allergies');
            const wMedicalConditionsField = document.getElementById('w_medicalConditions');
            const wDeferralReasonField = document.getElementById('w_deferralReason');
            const wEmergencyNameField = document.getElementById('w_emergencyContactName');
            const wEmergencyNumberField = document.getElementById('w_emergencyContactNumber');

            const newWeight = wWeightField && wWeightField.value.trim() !== '' ? wWeightField.value.trim() : 'N/A';
            const newEligibilityStatus = wEligibilityField ? wEligibilityField.value : 'Eligible';
            const newAllergies = wAllergiesField && wAllergiesField.value.trim() !== '' ? wAllergiesField.value.trim() : 'None';
            const newMedicalConditions = wMedicalConditionsField && wMedicalConditionsField.value.trim() !== '' ? wMedicalConditionsField.value.trim() : 'None';
            const newDeferralReason = wDeferralReasonField ? wDeferralReasonField.value.trim() : '';
            const newEmergencyContactName = wEmergencyNameField ? wEmergencyNameField.value.trim() : '';
            const newEmergencyContactNumber = wEmergencyNumberField ? wEmergencyNumberField.value.trim() : '';

            const newDonorObj = {
                id: newDonorId,
                name: fullName,
                firstName: fName,
                middleName: mName,
                surname: lName,
                ext: ext,
                bloodType: bloodType,
                brgy: brgy,
                verified: true,
                contact: contact,
                bday: bday,
                lastDonation: "N/A",
                timesDonated: "0",
                avatar: avatarSrc,
                weight: newWeight,
                allergies: newAllergies,
                medicalConditions: newMedicalConditions,
                eligibilityStatus: newEligibilityStatus,
                deferralReason: newDeferralReason,
                emergencyContactName: newEmergencyContactName,
                emergencyContactNumber: newEmergencyContactNumber,
                createdBy: getCurrentUserForAudit().name
            };

            // The "Creating..." state on the button now lasts for the WHOLE
            // save, not just an instant — it only clears once the server has
            // actually confirmed the donor was saved (or clearly failed),
            // the same way a file upload here in chat shows "Uploading..."
            // until it is truly done rather than clearing right away.
            const endCreatingState = () => {
                isCreatingDonor = false;
                if (createBtn) {
                    createBtn.disabled = false;
                    createBtn.style.opacity = '';
                    createBtn.style.cursor = '';
                    createBtn.innerHTML = createBtnOriginalText;
                }
            };

            apiRequest('/api/donors', 'POST', newDonorObj).then(data => {
                // Use the server's real saved row (with its real database id)
                // when available, so later edits/deletes reference the
                // correct row from the very start.
                const savedDonor = (data && data.donor) ? data.donor : newDonorObj;
                donorsData.push(savedDonor);
                localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                logAuditEvent('Create', savedDonor);
                renderDonorCards();
                updateStatisticsData();
                endCreatingState();
                showAlertBox('Donor successfully created! A History Record can be added once the donor actually donates.');
                resetDonorWizardForm();
                goToWizardStep(0);
                switchMainPage('home', document.querySelectorAll('.bottom-nav-item')[0]);
            }).catch(err => {
                // Offline / server unreachable: still keep the donor usable on
                // THIS device (matches the original offline-friendly design),
                // but say so plainly instead of pretending it fully saved.
                donorsData.push(newDonorObj);
                localStorage.setItem('redflow_donors_masterlist', JSON.stringify(donorsData));
                logAuditEvent('Create', newDonorObj);
                renderDonorCards();
                updateStatisticsData();
                endCreatingState();
                showAlertBox(err.isNetworkError
                    ? 'No internet connection. The donor was saved on this device only and will need to be re-added once you are back online.'
                    : 'Warning: Could not save this donor to the shared database. It is only saved on this device for now.');
                resetDonorWizardForm();
                goToWizardStep(0);
                switchMainPage('home', document.querySelectorAll('.bottom-nav-item')[0]);
            });
        }

        // NEW: Clears every field in the Add Donor wizard (Steps 1-4) so that
        // starting a new entry never shows leftover data from the donor that
        // was just created.
        function resetDonorWizardForm() {
            const textFieldIds = [
                'w_firstName', 'w_middleName', 'w_lastName', 'w_contact',
                'w_weight', 'w_allergies', 'w_medicalConditions',
                'w_deferralReason', 'w_emergencyContactName', 'w_emergencyContactNumber'
            ];
            textFieldIds.forEach(id => {
                const field = document.getElementById(id);
                if (field) field.value = '';
            });
            const contactField = document.getElementById('w_contact');
            if (contactField) contactField.value = '+63';

            const bdayField = document.getElementById('w_bday');
            if (bdayField) bdayField.value = '';

            const noMiddleBox = document.getElementById('w_noMiddle');
            if (noMiddleBox) noMiddleBox.checked = false;
            const middleField = document.getElementById('w_middleName');
            if (middleField) middleField.disabled = false;

            const selectDefaultIds = ['w_ext', 'w_bloodType', 'w_role', 'w_barangay'];
            selectDefaultIds.forEach(id => {
                const field = document.getElementById(id);
                if (field) field.selectedIndex = 0;
            });

            const eligibilityField = document.getElementById('w_eligibilityStatus');
            if (eligibilityField) eligibilityField.value = 'Eligible';

            // Medical Conditions is Admin-only — Staff shouldn't see or edit
            // it, on the Create Donor wizard just like on the Donor Profile View.
            const medicalConditionsWrap = document.getElementById('w_medicalConditions_wrap');
            if (medicalConditionsWrap) medicalConditionsWrap.style.display = isAdminUser() ? 'block' : 'none';

            const avatarPreview = document.getElementById('wizardAvatarPreview');
            if (avatarPreview) avatarPreview.src = 'picture.jpg';
        }

        let currentAboFilter = 'All';
        let currentBrgyFilter = 'All Brgys.';

        // Debounce helper: with a large donor masterlist, re-filtering and
        // re-rendering the whole list on every single keystroke can stutter.
        // Waits for a short pause in typing before actually running.
        function debounce(fn, delayMs = 250) {
            let timer = null;
            return function (...args) {
                clearTimeout(timer);
                timer = setTimeout(() => fn.apply(this, args), delayMs);
            };
        }

        function filterDonorsList() {
            const query = document.getElementById('donor-search-input').value.toLowerCase().trim();
            const filtered = donorsData.filter(donor => {
                const matchesSearch = donor.name.toLowerCase().includes(query) || 
                                      donor.brgy.toLowerCase().includes(query) || 
                                      donor.bloodType.toLowerCase().includes(query);
                const matchesAbo = (currentAboFilter === 'All' || donor.bloodType === currentAboFilter);
                const matchesBrgy = (currentBrgyFilter === 'All Brgys.' || donor.brgy === currentBrgyFilter);
                return matchesSearch && matchesAbo && matchesBrgy;
            });
            renderDonorCards(filtered);
        }
        const debouncedFilterDonorsList = debounce(filterDonorsList, 250);

        function filterByAbo(type) {
            currentAboFilter = type;
            toggleDropdown('abo-dropdown');
            filterDonorsList();
        }

        function filterByBrgy(brgy) {
            currentBrgyFilter = brgy;
            toggleDropdown('brgy-dropdown');
            filterDonorsList();
        }

        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'flex';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        // CUSTOM ALERT BOX - REPLACES PLAIN BROWSER showAlertBox() WITH A CLEARLY
        // VISIBLE STYLED CARD (SAME LOOK & FEEL AS THE LOGOUT CONFIRMATION BOX).
        function showAlertBox(message) {
            const card = document.getElementById('alertBoxCard');
            const icon = document.getElementById('alertBoxIcon');
            const title = document.getElementById('alertBoxTitle');
            const msgElem = document.getElementById('alertBoxMessage');

            let type = 'info';
            let iconClass = 'fa-solid fa-circle-info';
            let titleText = 'Notice';
            const lower = String(message).toLowerCase();
            if (lower.startsWith('error') || lower.includes('cannot') || lower.includes('incorrect') || lower.includes('not found') || lower.includes('rejected')) {
                type = 'error';
                iconClass = 'fa-solid fa-circle-exclamation';
                titleText = 'Error';
            } else if (lower.includes('successfully') && (lower.includes('deleted') || lower.includes('cleared') || lower.includes('removed'))) {
                // e.g. "Selected audit log entries deleted successfully!" —
                // this used to be caught by the word "select" below and
                // wrongly titled "Please Check".
                type = 'success';
                iconClass = 'fa-solid fa-trash-can';
                titleText = 'Record Deleted';
            } else if (lower.includes('please') || lower.includes('waiting for') || lower.includes('select')) {
                type = 'warning';
                iconClass = 'fa-solid fa-triangle-exclamation';
                titleText = 'Please Check';
            } else if (lower.includes('successfully') || lower.includes('approved') || lower.includes('created') || lower.includes('updated') || lower.includes('submitted') || lower.includes('logged')) {
                type = 'success';
                iconClass = 'fa-solid fa-circle-check';
                titleText = 'Success';
            }

            card.classList.remove('type-info', 'type-error', 'type-warning', 'type-success');
            card.classList.add('type-' + type);
            icon.innerHTML = `<i class="${iconClass}"></i>`;
            title.innerText = titleText;
            msgElem.innerText = message;
            openModal('alertBoxModal');
        }
    