const API_BASE_URL = window.location.origin;
let isLoggedIn = false;
let isAdmin = false;
let isMenuOpen = false;
let currentServiceId = null;
let contentCache = null;
let servicesCache = null;

async function apiCall(url, method = 'GET', body = null, auth = false) {
    const fullUrl = url.startsWith('http') ? url : `${API_BASE_URL}${url}`;
    const headers = { 'Content-Type': 'application/json' };
    const options = { method, headers, body: body ? JSON.stringify(body) : null, credentials: 'include' };
    try {
        const response = await fetch(fullUrl, options);
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            const message = data.message || `Ошибка: ${response.status} ${response.statusText}`;
            console.error(`API Error: Status ${response.status}, URL: ${fullUrl}, Message: ${message}`);
            if (response.status === 401 || response.status === 403) {
                if (url.includes('/login')) {
                    throw new Error(message); // Invalid credentials, show server message
                }
                isLoggedIn = false;
                isAdmin = false;
                updateNavLinks();
                openModal('auth');
                throw new Error('Сессия истекла. Пожалуйста, войдите снова.');
            }
            throw new Error(message);
        }
        return await response.json();
    } catch (e) {
        console.error('API Call Error:', e.message);
        throw e;
    }
}

function initPhoneMasks() {
    if (typeof IMask === 'undefined') {
        console.warn('IMask not loaded');
        return;
    }
    ['reg-phone', 'order-phone', 'cta-phone'].forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            IMask(input, {
                mask: '+70000000000',
                prepare: function (str) {
                    return str.replace(/[^0-9]/g, '');
                },
                commit: function (value, masked) {
                    if (value.length === 11 && (value.startsWith('7') || value.startsWith('8'))) {
                        masked.value = '+7' + value.slice(1);
                    } else if (value.length === 10) {
                        masked.value = '+7' + value;
                    }
                }
            });
        }
    });
}

function toggleMenu() {
    isMenuOpen = !isMenuOpen;
    document.querySelector('.nav-menu').classList.toggle('active', isMenuOpen);
}

function openModal(form, serviceId = null) {
    document.querySelectorAll('.modal-content > div').forEach(el => el.style.display = 'none');
    document.getElementById(`${form}-form`).style.display = 'block';
    document.getElementById('modal').classList.add('active');
    document.body.style.overflow = 'hidden';
    if (form === 'order') fetchServicesForOrder();
    if (form === 'edit-service' && serviceId) {
        currentServiceId = serviceId;
        fetchServiceForEdit(serviceId);
    }
    initPhoneMasks();
}

function closeModal() {
    document.getElementById('modal').classList.remove('active');
    document.body.style.overflow = 'auto';
    document.querySelectorAll('.modal .error, .modal .success').forEach(el => el.textContent = '');
    document.querySelectorAll('.modal input, .modal textarea, .modal select').forEach(el => el.value = '');
    currentServiceId = null;
}

function showToast(message, isError = false) {
    const toast = document.getElementById('toast');
    document.getElementById('toast-message').textContent = message;
    toast.classList.remove('success', 'error');
    toast.classList.add(isError ? 'error' : 'success', 'active');
    setTimeout(() => toast.classList.remove('active'), 3000);
}

function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) element.textContent = message;
    showToast(message, true);
}

function hideAll() {
    document.querySelectorAll('.fade-in').forEach(el => el.style.display = 'none');
    closeModal();
    if (isMenuOpen) toggleMenu();
}

function showHome() {
    hideAll();
    document.getElementById('home-page').style.display = 'block';
    fetchContent();
}

function showAbout() {
    hideAll();
    document.getElementById('about-page').style.display = 'block';
    fetchContent();
}

function showServices() {
    hideAll();
    document.getElementById('services-page').style.display = 'block';
    fetchServices();
}

function showOrders() {
    if (!isLoggedIn) return openModal('auth');
    hideAll();
    document.getElementById('orders-page').style.display = 'block';
    fetchOrders();
}

function showAdminPanel(tab = 'orders') {
    if (!isLoggedIn) return openModal('auth');
    if (!isAdmin) return showToast('Доступ только для администраторов', true);
    hideAll();
    document.getElementById('admin-panel').style.display = 'block';
    showAdminTab(tab);
}

function showAdminTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('#admin-orders, #admin-users, #admin-content').forEach(el => el.style.display = 'none');
    document.getElementById(`tab-${tab}`).classList.add('active');
    document.getElementById(`admin-${tab}`).style.display = 'block';
    if (tab === 'orders') fetchAdminOrders();
    if (tab === 'users') fetchUsers();
    if (tab === 'content') {
        fetchContent(true);
        fetchServices(true);
    }
}

function updateNavLinks() {
    const authLink = document.getElementById('auth-link');
    const ordersLink = document.querySelectorAll('.orders-link');
    if (isLoggedIn) {
        authLink.textContent = isAdmin ? 'Админ-панель' : 'Профиль';
        authLink.onclick = () => isAdmin ? showAdminPanel() : showOrders();
        ordersLink.forEach(link => link.style.display = 'block');
    } else {
        authLink.textContent = 'Вход';
        authLink.onclick = () => openModal('auth');
        ordersLink.forEach(link => link.style.display = 'none');
    }
}

async function fetchContent(forAdmin = false) {
    if (contentCache && !forAdmin) {
        renderContent(contentCache);
        return;
    }
    try {
        const data = await apiCall('/api/content');
        contentCache = data;
        renderContent(data, forAdmin);
    } catch (e) {
        showToast('Ошибка загрузки контента', true);
    }
}

function renderContent(data, forAdmin = false) {
    document.getElementById('home-title').textContent = data.home_title || 'Чистота с любовью!';
    document.getElementById('home-subtitle').textContent = data.home_subtitle || 'Профессиональная уборка для дома и офиса.';
    document.getElementById('about-content').textContent = data.about_content || '«Мой Не Сам» — команда профессионалов, делающая дома и офисы чище с 2023 года.';
    if (forAdmin) {
        document.getElementById('content-home-title').value = data.home_title || '';
        document.getElementById('content-home-subtitle').value = data.home_subtitle || '';
        document.getElementById('content-about').value = data.about_content || '';
    }
}

async function fetchServices(forAdmin = false) {
    if (servicesCache && !forAdmin) {
        renderServices(servicesCache);
        return;
    }
    try {
        const data = await apiCall('/api/services');
        servicesCache = data;
        renderServices(data, forAdmin);
    } catch (e) {
        showToast('Ошибка загрузки услуг', true);
    }
}

function renderServices(services, forAdmin = false) {
    const container = forAdmin ? document.getElementById('admin-services-table-body') : document.getElementById('services-list');
    container.innerHTML = '';
    services.forEach(service => {
        if (forAdmin) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><img src="${service.photo_url}" alt="${service.name}" class="service-img"></td>
                <td>${service.name}</td>
                <td>${service.description || ''}</td>
                <td>
                    <button class="btn btn-primary" onclick="openModal('edit-service', ${service.id})">Редактировать</button>
                    <button class="btn btn-red" onclick="deleteService(${service.id})">Удалить</button>
                </td>
            `;
            container.appendChild(row);
        } else {
            const card = document.createElement('div');
            card.className = 'card';
            card.innerHTML = `
                <img src="${service.photo_url}" alt="${service.name}" loading="lazy">
                <h3>${service.name}</h3>
                <p>${service.description || ''}</p>
            `;
            container.appendChild(card);
        }
    });
}

async function fetchServicesForOrder() {
    try {
        const services = await apiCall('/api/services');
        const select = document.getElementById('order-service');
        select.innerHTML = '<option value="">Выберите услугу</option>';
        services.forEach(service => {
            const option = document.createElement('option');
            option.value = service.name;
            option.textContent = service.name;
            select.appendChild(option);
        });
    } catch (e) {
        showError('order-error', 'Ошибка загрузки услуг');
    }
}

async function fetchServiceForEdit(id) {
    try {
        const services = await apiCall('/api/services');
        const service = services.find(s => s.id === id);
        if (service) {
            document.getElementById('edit-service-name').value = service.name;
            document.getElementById('edit-service-photo').value = service.photo_url;
            document.getElementById('edit-service-description').value = service.description || '';
        }
    } catch (e) {
        showError('edit-service-error', 'Ошибка загрузки услуги');
    }
}

async function fetchOrders() {
    try {
        const orders = await apiCall('/api/orders', 'GET', null, true);
        renderOrders(orders);
    } catch (e) {
        showToast('Ошибка загрузки заявок', true);
    }
}

function renderOrders(orders) {
    const tbody = document.getElementById('orders-table-body');
    tbody.innerHTML = '';
    orders.forEach(order => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${order.address}</td>
            <td>${order.service_type}${order.other_service ? ` (${order.other_service})` : ''}</td>
            <td>${new Date(order.date_time).toLocaleString()}</td>
            <td>${order.payment_type}</td>
            <td>${order.status}${order.cancel_reason ? ` (${order.cancel_reason})` : ''}</td>
        `;
        tbody.appendChild(row);
    });
}

async function fetchAdminOrders() {
    try {
        const orders = await apiCall('/api/admin-orders', 'GET', null, true);
        renderAdminOrders(orders);
    } catch (e) {
        showToast('Ошибка загрузки заявок', true);
    }
}

function renderAdminOrders(orders) {
    const tbody = document.getElementById('admin-orders-table-body');
    tbody.innerHTML = '';
    orders.forEach(order => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${order.full_name}</td>
            <td>${order.address}</td>
            <td>${order.phone}</td>
            <td>${order.service_type}${order.other_service ? ` (${order.other_service})` : ''}</td>
            <td>${new Date(order.date_time).toLocaleString()}</td>
            <td>${order.payment_type}</td>
            <td>
                <select onchange="updateOrderStatus(${order.id}, this.value)">
                    <option value="новая" ${order.status === 'новая' ? 'selected' : ''}>Новая</option>
                    <option value="в работе" ${order.status === 'в работе' ? 'selected' : ''}>В работе</option>
                    <option value="выполнено" ${order.status === 'выполнено' ? 'selected' : ''}>Выполнено</option>
                    <option value="отменено" ${order.status === 'отменено' ? 'selected' : ''}>Отменено</option>
                </select>
            </td>
            <td>
                <input type="text" value="${order.cancel_reason || ''}" onchange="updateCancelReason(${order.id}, this.value)">
            </td>
            <td></td>
        `;
        tbody.appendChild(row);
    });
}

async function fetchUsers() {
    try {
        const users = await apiCall('/api/users', 'GET', null, true);
        renderUsers(users);
    } catch (e) {
        showToast('Ошибка загрузки пользователей', true);
    }
}

function renderUsers(users) {
    const tbody = document.getElementById('admin-users-table-body');
    tbody.innerHTML = '';
    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.login}</td>
            <td>${user.full_name}</td>
            <td>${user.phone}</td>
            <td>${user.email}</td>
            <td>
                <button class="btn btn-red" onclick="deleteUser(${user.id})">Удалить</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function register() {
    const btn = document.getElementById('register-submit-btn');
    const btnText = document.getElementById('reg-btn-text');
    const spinner = document.getElementById('reg-btn-spinner');
    btn.disabled = true;
    btnText.textContent = 'Загрузка...';
    spinner.style.display = 'inline-block';
    try {
        const body = {
            login: document.getElementById('reg-login').value.trim(),
            password: document.getElementById('reg-password').value.trim(),
            full_name: document.getElementById('reg-fullname').value.trim(),
            phone: document.getElementById('reg-phone').value.trim(),
            email: document.getElementById('reg-email').value.trim()
        };
        await apiCall('/api/register', 'POST', body);
        showToast('Регистрация успешна! Пожалуйста, войдите.');
        openModal('auth');
    } catch (e) {
        showError('register-error', e.message);
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Зарегистрироваться';
        spinner.style.display = 'none';
    }
}

async function login() {
    const btn = document.getElementById('auth-submit-btn');
    const btnText = document.getElementById('auth-btn-text');
    const spinner = document.getElementById('auth-btn-spinner');
    btn.disabled = true;
    btnText.textContent = 'Загрузка...';
    spinner.style.display = 'inline-block';
    try {
        const body = {
            login: document.getElementById('auth-login').value.trim(),
            password: document.getElementById('auth-password').value.trim()
        };
        const data = await apiCall('/api/login', 'POST', body);
        isLoggedIn = true;
        isAdmin = data.isAdmin;
        updateNavLinks();
        closeModal();
        showToast('Вход успешен!');
        if (isAdmin) {
            showAdminPanel();
        } else {
            showOrders();
        }
    } catch (e) {
        showError('auth-error', e.message);
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Войти';
        spinner.style.display = 'none';
    }
}

async function logout() {
    try {
        await apiCall('/api/logout', 'POST', null, true);
        isLoggedIn = false;
        isAdmin = false;
        updateNavLinks();
        showToast('Выход выполнен');
        showHome();
    } catch (e) {
        showToast('Ошибка выхода', true);
    }
}

async function submitOrder() {
    const btn = document.getElementById('order-submit-btn');
    const btnText = document.getElementById('order-btn-text');
    const spinner = document.getElementById('order-btn-spinner');
    btn.disabled = true;
    btnText.textContent = 'Загрузка...';
    spinner.style.display = 'inline-block';
    try {
        const body = {
            address: document.getElementById('order-address').value.trim(),
            phone: document.getElementById('order-phone').value.trim(),
            service_type: document.getElementById('order-service').value,
            other_service: document.getElementById('other-service-check').checked ? document.getElementById('other-service').value.trim() : '',
            date_time: document.getElementById('order-datetime').value,
            payment_type: document.getElementById('order-payment').value
        };
        await apiCall('/api/orders', 'POST', body, true);
        closeModal();
        showToast('Заявка создана!');
        showOrders();
    } catch (e) {
        showError('order-error', e.message);
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Отправить';
        spinner.style.display = 'none';
    }
}

async function submitCta() {
    const btn = document.getElementById('cta-submit-btn');
    const btnText = document.getElementById('cta-btn-text');
    const spinner = document.getElementById('cta-btn-spinner');
    btn.disabled = true;
    btnText.textContent = 'Загрузка...';
    spinner.style.display = 'inline-block';
    try {
        const body = {
            name: document.getElementById('cta-name').value.trim(),
            phone: document.getElementById('cta-phone').value.trim()
        };
        await apiCall('/api/cta', 'POST', body);
        document.getElementById('cta-success').textContent = 'Заявка отправлена!';
        document.getElementById('cta-name').value = '';
        document.getElementById('cta-phone').value = '';
        showToast('Заявка отправлена!');
    } catch (e) {
        showError('cta-error', e.message);
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Отправить заявку';
        spinner.style.display = 'none';
    }
}

async function addService() {
    const btn = document.getElementById('new-service').parentElement.querySelector('.btn-primary');
    btn.disabled = true;
    try {
        const body = {
            name: document.getElementById('new-service').value.trim(),
            photo_url: document.getElementById('new-service-photo').value.trim(),
            description: document.getElementById('new-service-description').value.trim()
        };
        await apiCall('/api/services', 'POST', body, true);
        document.getElementById('new-service').value = '';
        document.getElementById('new-service-photo').value = '';
        document.getElementById('new-service-description').value = '';
        servicesCache = null;
        fetchServices(true);
        showToast('Услуга добавлена!');
    } catch (e) {
        showError('services-error', e.message);
    } finally {
        btn.disabled = false;
    }
}

async function updateService() {
    const btn = document.getElementById('edit-service-submit-btn');
    const btnText = document.getElementById('edit-service-btn-text');
    const spinner = document.getElementById('edit-service-btn-spinner');
    btn.disabled = true;
    btnText.textContent = 'Загрузка...';
    spinner.style.display = 'inline-block';
    try {
        const body = {
            name: document.getElementById('edit-service-name').value.trim(),
            photo_url: document.getElementById('edit-service-photo').value.trim(),
            description: document.getElementById('edit-service-description').value.trim()
        };
        await apiCall(`/api/services/${currentServiceId}`, 'PUT', body, true);
        closeModal();
        servicesCache = null;
        fetchServices(true);
        showToast('Услуга обновлена!');
    } catch (e) {
        showError('edit-service-error', e.message);
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Сохранить';
        spinner.style.display = 'none';
    }
}

async function deleteService(id) {
    if (!confirm('Вы уверены, что хотите удалить эту услугу?')) return;
    try {
        await apiCall(`/api/services/${id}`, 'DELETE', null, true);
        servicesCache = null;
        fetchServices(true);
        showToast('Услуга удалена!');
    } catch (e) {
        showToast('Ошибка удаления услуги', true);
    }
}

async function updateOrderStatus(id, status) {
    try {
        await apiCall('/api/admin-orders', 'PATCH', { id, status }, true);
        showToast('Статус обновлен!');
    } catch (e) {
        showToast('Ошибка обновления статуса', true);
        fetchAdminOrders();
    }
}

async function updateCancelReason(id, cancel_reason) {
    try {
        await apiCall('/api/admin-orders', 'PATCH', { id, cancel_reason }, true);
        showToast('Причина отмены обновлена!');
    } catch (e) {
        showToast('Ошибка обновления причины', true);
        fetchAdminOrders();
    }
}

async function deleteUser(id) {
    if (!confirm('Вы уверены, что хотите удалить этого пользователя?')) return;
    try {
        await apiCall(`/api/users/${id}`, 'DELETE', null, true);
        fetchUsers();
        showToast('Пользователь удален!');
    } catch (e) {
        showToast('Ошибка удаления пользователя', true);
    }
}

async function updateContent() {
    const btn = document.getElementById('content-home-title').parentElement.querySelector('.btn-primary');
    btn.disabled = true;
    try {
        const body = {
            home_title: document.getElementById('content-home-title').value.trim(),
            home_subtitle: document.getElementById('content-home-subtitle').value.trim(),
            about_content: document.getElementById('content-about').value.trim()
        };
        await apiCall('/api/content', 'PUT', body, true);
        contentCache = null;
        fetchContent(true);
        showToast('Контент обновлен!');
    } catch (e) {
        showError('content-error', e.message);
    } finally {
        btn.disabled = false;
    }
}

function toggleOtherService() {
    const checkbox = document.getElementById('other-service-check');
    const textarea = document.getElementById('other-service');
    const select = document.getElementById('order-service');
    textarea.style.display = checkbox.checked ? 'block' : 'none';
    select.disabled = checkbox.checked;
    if (checkbox.checked) select.value = '';
}

function toggleFaq(element) {
    const faqItem = element.parentElement;
    const isActive = faqItem.classList.contains('active');
    document.querySelectorAll('.faq-item').forEach(item => {
        item.classList.remove('active');
        item.querySelector('p').style.maxHeight = '0';
    });
    if (!isActive) {
        faqItem.classList.add('active');
        const p = faqItem.querySelector('p');
        p.style.maxHeight = `${p.scrollHeight}px`;
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateNavLinks();
    showHome();
    initPhoneMasks();
    // Check session status
    apiCall('/api/check-session', 'GET', null, true)
        .then(data => {
            isLoggedIn = true;
            isAdmin = data.isAdmin;
            updateNavLinks();
            if (isAdmin) showAdminPanel();
            else showOrders();
        })
        .catch(() => {
            isLoggedIn = false;
            isAdmin = false;
            updateNavLinks();
        });
});