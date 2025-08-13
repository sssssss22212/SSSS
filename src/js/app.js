// Import styles
import '../css/styles.css';

// Import libraries
import axios from 'axios';
import localforage from 'localforage';

// App Configuration
const CONFIG = {
    API_BASE_URL: 'https://your-backend-url.com/api', // Замените на ваш бэкенд URL
    STEAM_API_KEY: 'C3B55B7626C9DED8DA7B0D1F3F770806',
    YOOMONEY_WALLET: '4100117158431008',
    VERSION: '1.0.0',
    DEBUG: true
};

// App State
let appState = {
    user: null,
    isAuthenticated: false,
    currentPage: 'auth',
    servers: [],
    news: [],
    privileges: {},
    loading: false
};

// Initialize LocalForage for offline storage
localforage.config({
    name: 'DXProjectMobile',
    version: 1.0,
    storeName: 'dxproject_data'
});

// Utility Functions
const utils = {
    log: (message, data = null) => {
        if (CONFIG.DEBUG) {
            console.log(`[DX Project] ${message}`, data);
        }
    },
    
    error: (message, error = null) => {
        console.error(`[DX Project Error] ${message}`, error);
    },
    
    formatDate: (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleDateString('ru-RU', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    },
    
    formatCurrency: (amount) => {
        return `${amount}₽`;
    },
    
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    generateId: () => {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }
};

// Toast Notification System
class Toast {
    static show(message, type = 'info', duration = 3000) {
        const toastContainer = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        toastContainer.appendChild(toast);
        
        // Trigger animation
        setTimeout(() => toast.classList.add('show'), 100);
        
        // Auto remove
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                if (toastContainer.contains(toast)) {
                    toastContainer.removeChild(toast);
                }
            }, 300);
        }, duration);
        
        utils.log(`Toast: ${type} - ${message}`);
    }
    
    static success(message) {
        this.show(message, 'success');
    }
    
    static error(message) {
        this.show(message, 'error');
    }
    
    static warning(message) {
        this.show(message, 'warning');
    }
}

// Loading Manager
class LoadingManager {
    static show(text = 'Загрузка...') {
        const overlay = document.getElementById('loading-overlay');
        const loadingText = overlay.querySelector('.loading-text');
        loadingText.textContent = text;
        overlay.style.display = 'flex';
        appState.loading = true;
    }
    
    static hide() {
        const overlay = document.getElementById('loading-overlay');
        overlay.style.display = 'none';
        appState.loading = false;
    }
}

// API Service
class APIService {
    static async request(endpoint, options = {}) {
        const url = `${CONFIG.API_BASE_URL}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'X-App-Version': CONFIG.VERSION
            }
        };
        
        // Add auth token if available
        if (appState.user && appState.user.token) {
            defaultOptions.headers['Authorization'] = `Bearer ${appState.user.token}`;
        }
        
        const finalOptions = { ...defaultOptions, ...options };
        
        try {
            utils.log(`API Request: ${options.method || 'GET'} ${url}`);
            const response = await axios(url, finalOptions);
            utils.log(`API Response: ${response.status}`, response.data);
            return response.data;
        } catch (error) {
            utils.error(`API Error: ${endpoint}`, error);
            
            if (error.response) {
                // Server responded with error
                throw new Error(error.response.data.message || 'Ошибка сервера');
            } else if (error.request) {
                // Network error
                throw new Error('Ошибка сети. Проверьте подключение к интернету.');
            } else {
                throw new Error('Произошла неожиданная ошибка');
            }
        }
    }
    
    static async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }
    
    static async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            data
        });
    }
    
    static async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            data
        });
    }
    
    static async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
}

// Authentication Service
class AuthService {
    static async login(email, password) {
        try {
            LoadingManager.show('Вход в систему...');
            
            const response = await APIService.post('/auth/login', {
                email,
                password
            });
            
            await this.setUser(response.user, response.token);
            return response.user;
        } catch (error) {
            throw error;
        } finally {
            LoadingManager.hide();
        }
    }
    
    static async register(name, email, password, confirmPassword) {
        if (password !== confirmPassword) {
            throw new Error('Пароли не совпадают');
        }
        
        try {
            LoadingManager.show('Регистрация...');
            
            const response = await APIService.post('/auth/register', {
                name,
                email,
                password,
                confirm_password: confirmPassword
            });
            
            await this.setUser(response.user, response.token);
            return response.user;
        } catch (error) {
            throw error;
        } finally {
            LoadingManager.hide();
        }
    }
    
    static async loginWithSteam() {
        try {
            LoadingManager.show('Авторизация через Steam...');
            
            // Open Steam auth in InAppBrowser
            if (window.cordova && window.cordova.InAppBrowser) {
                const steamUrl = await APIService.get('/auth/steam/url');
                const browser = window.cordova.InAppBrowser.open(steamUrl.url, '_blank', 'location=yes');
                
                browser.addEventListener('loadstop', (event) => {
                    if (event.url.includes('/auth/steam/callback')) {
                        browser.executeScript({
                            code: 'document.body.innerText'
                        }, (result) => {
                            try {
                                const data = JSON.parse(result[0]);
                                if (data.user && data.token) {
                                    this.setUser(data.user, data.token);
                                    browser.close();
                                    Toast.success('Успешная авторизация через Steam!');
                                    App.showScreen('main');
                                }
                            } catch (e) {
                                Toast.error('Ошибка авторизации через Steam');
                                browser.close();
                            }
                        });
                    }
                });
            } else {
                // Fallback for web version
                Toast.warning('Steam авторизация доступна только в мобильном приложении');
            }
        } catch (error) {
            Toast.error(error.message);
        } finally {
            LoadingManager.hide();
        }
    }
    
    static async setUser(user, token) {
        appState.user = { ...user, token };
        appState.isAuthenticated = true;
        
        // Save to local storage
        await localforage.setItem('user', appState.user);
        await localforage.setItem('isAuthenticated', true);
        
        // Update UI
        this.updateUserUI();
        
        utils.log('User authenticated', user);
    }
    
    static async logout() {
        appState.user = null;
        appState.isAuthenticated = false;
        
        // Clear local storage
        await localforage.removeItem('user');
        await localforage.removeItem('isAuthenticated');
        
        // Update UI
        this.updateUserUI();
        App.showScreen('auth');
        
        Toast.success('Вы успешно вышли из системы');
        utils.log('User logged out');
    }
    
    static async loadStoredAuth() {
        try {
            const user = await localforage.getItem('user');
            const isAuthenticated = await localforage.getItem('isAuthenticated');
            
            if (user && isAuthenticated) {
                appState.user = user;
                appState.isAuthenticated = true;
                this.updateUserUI();
                return true;
            }
        } catch (error) {
            utils.error('Failed to load stored auth', error);
        }
        return false;
    }
    
    static updateUserUI() {
        const userNameElements = document.querySelectorAll('#user-name');
        const userBalanceElements = document.querySelectorAll('#user-balance');
        const userAvatarElements = document.querySelectorAll('#user-avatar-img');
        
        if (appState.isAuthenticated && appState.user) {
            userNameElements.forEach(el => el.textContent = appState.user.name);
            userBalanceElements.forEach(el => el.textContent = utils.formatCurrency(appState.user.balance || 0));
            userAvatarElements.forEach(el => {
                if (appState.user.avatar) {
                    el.src = appState.user.avatar;
                }
            });
        } else {
            userNameElements.forEach(el => el.textContent = 'Гость');
            userBalanceElements.forEach(el => el.textContent = '0₽');
            userAvatarElements.forEach(el => el.src = 'assets/images/default-avatar.png');
        }
    }
}

// Data Service
class DataService {
    static async loadServers() {
        try {
            const servers = await APIService.get('/servers');
            appState.servers = servers;
            await localforage.setItem('servers', servers);
            return servers;
        } catch (error) {
            // Try to load from cache
            const cachedServers = await localforage.getItem('servers');
            if (cachedServers) {
                appState.servers = cachedServers;
                return cachedServers;
            }
            throw error;
        }
    }
    
    static async loadNews() {
        try {
            const news = await APIService.get('/news');
            appState.news = news;
            await localforage.setItem('news', news);
            return news;
        } catch (error) {
            const cachedNews = await localforage.getItem('news');
            if (cachedNews) {
                appState.news = cachedNews;
                return cachedNews;
            }
            throw error;
        }
    }
    
    static async loadPrivileges() {
        try {
            const privileges = await APIService.get('/privileges');
            appState.privileges = privileges;
            await localforage.setItem('privileges', privileges);
            return privileges;
        } catch (error) {
            const cachedPrivileges = await localforage.getItem('privileges');
            if (cachedPrivileges) {
                appState.privileges = cachedPrivileges;
                return cachedPrivileges;
            }
            throw error;
        }
    }
    
    static async updateServerStatus() {
        try {
            const servers = await APIService.get('/servers/status');
            appState.servers = servers;
            await localforage.setItem('servers', servers);
            return servers;
        } catch (error) {
            utils.error('Failed to update server status', error);
            return appState.servers;
        }
    }
}

// Payment Service
class PaymentService {
    static async createPayment(amount, method = 'yoomoney') {
        try {
            LoadingManager.show('Создание платежа...');
            
            const payment = await APIService.post('/payments/create', {
                amount,
                method,
                user_id: appState.user.id
            });
            
            return payment;
        } catch (error) {
            throw error;
        } finally {
            LoadingManager.hide();
        }
    }
    
    static async processYooMoneyPayment(amount) {
        try {
            const payment = await this.createPayment(amount, 'yoomoney');
            
            const paymentUrl = `https://yoomoney.ru/quickpay/confirm.xml?` + new URLSearchParams({
                receiver: CONFIG.YOOMONEY_WALLET,
                'quickpay-form': 'shop',
                targets: 'Пополнение баланса DX Project',
                paymentType: 'AC',
                sum: amount,
                label: `${appState.user.id}:${payment.id}`,
                successURL: window.location.origin + '/?payment=success',
                failURL: window.location.origin + '/?payment=fail'
            });
            
            if (window.cordova && window.cordova.InAppBrowser) {
                const browser = window.cordova.InAppBrowser.open(paymentUrl, '_blank', 'location=yes');
                
                browser.addEventListener('loadstop', (event) => {
                    if (event.url.includes('payment=success')) {
                        browser.close();
                        Toast.success('Платеж успешно обработан!');
                        this.checkPaymentStatus(payment.id);
                    } else if (event.url.includes('payment=fail')) {
                        browser.close();
                        Toast.error('Ошибка при обработке платежа');
                    }
                });
            } else {
                window.open(paymentUrl, '_blank');
            }
        } catch (error) {
            Toast.error(error.message);
        }
    }
    
    static async checkPaymentStatus(paymentId) {
        try {
            const status = await APIService.get(`/payments/${paymentId}/status`);
            
            if (status.completed) {
                // Update user balance
                appState.user.balance = status.new_balance;
                await localforage.setItem('user', appState.user);
                AuthService.updateUserUI();
                Toast.success('Баланс успешно пополнен!');
            }
        } catch (error) {
            utils.error('Failed to check payment status', error);
        }
    }
    
    static async buyPrivilege(privilegeId, duration = 1) {
        try {
            LoadingManager.show('Покупка привилегии...');
            
            const result = await APIService.post('/privileges/buy', {
                privilege_id: privilegeId,
                duration,
                user_id: appState.user.id
            });
            
            // Update user data
            appState.user.balance = result.new_balance;
            appState.user.privileges = result.privileges;
            await localforage.setItem('user', appState.user);
            AuthService.updateUserUI();
            
            Toast.success(`Привилегия "${result.privilege_name}" успешно активирована!`);
            return result;
        } catch (error) {
            throw error;
        } finally {
            LoadingManager.hide();
        }
    }
}

// Screen Manager
class ScreenManager {
    static showScreen(screenName) {
        // Hide all screens
        document.querySelectorAll('.screen').forEach(screen => {
            screen.classList.remove('active');
        });
        
        // Show target screen
        const targetScreen = document.getElementById(`${screenName}-screen`);
        if (targetScreen) {
            targetScreen.classList.add('active');
            targetScreen.classList.add('animate-fade-in');
        }
        
        // Update navigation
        this.updateNavigation(screenName);
        
        // Update page title
        this.updatePageTitle(screenName);
        
        // Load screen data
        this.loadScreenData(screenName);
        
        appState.currentPage = screenName;
        utils.log(`Screen changed to: ${screenName}`);
    }
    
    static updateNavigation(screenName) {
        // Update menu items
        document.querySelectorAll('.menu-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.page === screenName) {
                item.classList.add('active');
            }
        });
        
        // Update bottom nav
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.page === screenName) {
                item.classList.add('active');
            }
        });
    }
    
    static updatePageTitle(screenName) {
        const titles = {
            main: 'Главная',
            servers: 'Сервера',
            donate: 'Донат',
            rules: 'Правила',
            applications: 'Заявки',
            news: 'Новости',
            profile: 'Профиль'
        };
        
        const titleElement = document.getElementById('page-title');
        if (titleElement && titles[screenName]) {
            titleElement.textContent = titles[screenName];
        }
    }
    
    static async loadScreenData(screenName) {
        try {
            switch (screenName) {
                case 'servers':
                    await this.loadServersScreen();
                    break;
                case 'donate':
                    await this.loadDonateScreen();
                    break;
                case 'news':
                    await this.loadNewsScreen();
                    break;
                case 'profile':
                    await this.loadProfileScreen();
                    break;
            }
        } catch (error) {
            utils.error(`Failed to load ${screenName} screen data`, error);
        }
    }
    
    static async loadServersScreen() {
        const screen = document.getElementById('servers-screen');
        if (!screen) return;
        
        try {
            const servers = await DataService.loadServers();
            
            screen.innerHTML = `
                <div class="screen-content">
                    <h1>🔥 Наши сервера</h1>
                    <div class="servers-list">
                        ${servers.map(server => `
                            <div class="server-card animate-slide-in-left">
                                <div class="server-header">
                                    <h3>${server.name}</h3>
                                    <div class="server-status ${server.online > 0 ? 'online' : 'offline'}">
                                        ${server.online}/${server.max_players}
                                    </div>
                                </div>
                                <div class="server-ip" onclick="navigator.clipboard.writeText('${server.ip}')">
                                    IP: ${server.ip}
                                </div>
                                <p>${server.description || ''}</p>
                                ${server.features ? `
                                    <div class="server-features">
                                        <h4>Особенности:</h4>
                                        <ul>
                                            ${server.features.map(feature => `<li>${feature}</li>`).join('')}
                                        </ul>
                                    </div>
                                ` : ''}
                            </div>
                        `).join('')}
                    </div>
                    <button class="btn btn-primary" onclick="DataService.updateServerStatus().then(() => ScreenManager.loadServersScreen())">
                        🔄 Обновить статус
                    </button>
                </div>
            `;
        } catch (error) {
            screen.innerHTML = `
                <div class="screen-content">
                    <div class="error-state">
                        <h2>Ошибка загрузки</h2>
                        <p>Не удалось загрузить информацию о серверах</p>
                        <button class="btn btn-primary" onclick="ScreenManager.loadServersScreen()">
                            Повторить
                        </button>
                    </div>
                </div>
            `;
        }
    }
    
    static async loadDonateScreen() {
        const screen = document.getElementById('donate-screen');
        if (!screen) return;
        
        try {
            const privileges = await DataService.loadPrivileges();
            
            screen.innerHTML = `
                <div class="screen-content">
                    <h1>💎 Донат система</h1>
                    <p>Поддержи любимый сервер и получи уникальные возможности!</p>
                    
                    <div class="balance-card">
                        <h3>💰 Ваш баланс</h3>
                        <div class="balance-amount">${utils.formatCurrency(appState.user?.balance || 0)}</div>
                        <button class="btn btn-primary" onclick="App.showTopUpModal()">
                            Пополнить баланс
                        </button>
                    </div>
                    
                    <div class="privileges-list">
                        ${Object.entries(privileges).map(([id, priv]) => `
                            <div class="privilege-card">
                                <h3 style="color: ${priv.color || '#dc143c'}">${priv.name}</h3>
                                <div class="privilege-price">${utils.formatCurrency(priv.price)}/мес</div>
                                <div class="privilege-features">
                                    ${priv.features ? priv.features.map(feature => `
                                        <div class="feature-item">⚡ ${feature}</div>
                                    `).join('') : ''}
                                </div>
                                <button class="btn btn-primary" onclick="PaymentService.buyPrivilege('${id}')">
                                    Купить
                                </button>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } catch (error) {
            screen.innerHTML = `
                <div class="screen-content">
                    <div class="error-state">
                        <h2>Ошибка загрузки</h2>
                        <p>Не удалось загрузить информацию о донате</p>
                        <button class="btn btn-primary" onclick="ScreenManager.loadDonateScreen()">
                            Повторить
                        </button>
                    </div>
                </div>
            `;
        }
    }
    
    static async loadNewsScreen() {
        const screen = document.getElementById('news-screen');
        if (!screen) return;
        
        try {
            const news = await DataService.loadNews();
            
            screen.innerHTML = `
                <div class="screen-content">
                    <h1>📰 Новости проекта</h1>
                    <div class="news-list">
                        ${news.length > 0 ? news.map(item => `
                            <div class="news-item animate-slide-in-left">
                                <h3>${item.title}</h3>
                                <div class="news-meta">
                                    👤 ${item.author} | 📅 ${utils.formatDate(item.date)}
                                </div>
                                <div class="news-content">
                                    ${item.content.replace(/\n/g, '<br>')}
                                </div>
                                ${item.image ? `<img src="${item.image}" alt="News Image" class="news-image">` : ''}
                                ${item.link && item.link_text ? `
                                    <a href="${item.link}" target="_blank" class="btn btn-primary">
                                        🔗 ${item.link_text}
                                    </a>
                                ` : ''}
                            </div>
                        `).join('') : `
                            <div class="empty-state">
                                <h3>📭 Новостей пока нет</h3>
                                <p>Следите за обновлениями!</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        } catch (error) {
            screen.innerHTML = `
                <div class="screen-content">
                    <div class="error-state">
                        <h2>Ошибка загрузки</h2>
                        <p>Не удалось загрузить новости</p>
                        <button class="btn btn-primary" onclick="ScreenManager.loadNewsScreen()">
                            Повторить
                        </button>
                    </div>
                </div>
            `;
        }
    }
    
    static async loadProfileScreen() {
        const screen = document.getElementById('profile-screen');
        if (!screen || !appState.isAuthenticated) return;
        
        screen.innerHTML = `
            <div class="screen-content">
                <h1>👤 Личный кабинет</h1>
                
                <div class="profile-card">
                    <div class="profile-header">
                        <img src="${appState.user.avatar || 'assets/images/default-avatar.png'}" alt="Avatar" class="profile-avatar">
                        <div class="profile-info">
                            <h2>${appState.user.name}</h2>
                            <p>${appState.user.email}</p>
                            <div class="balance-info">
                                Баланс: ${utils.formatCurrency(appState.user.balance || 0)}
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="profile-sections">
                    <div class="profile-section">
                        <h3>💰 Пополнение баланса</h3>
                        <button class="btn btn-primary" onclick="App.showTopUpModal()">
                            Пополнить баланс
                        </button>
                    </div>
                    
                    ${appState.user.privileges ? `
                        <div class="profile-section">
                            <h3>💎 Мои привилегии</h3>
                            <div class="privileges-list">
                                ${Object.entries(appState.user.privileges).map(([id, priv]) => `
                                    <div class="privilege-item">
                                        <span>${priv.name}</span>
                                        <span class="privilege-expires">
                                            ${priv.expires ? `До ${utils.formatDate(priv.expires)}` : 'Навсегда'}
                                        </span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                    
                    <div class="profile-section">
                        <h3>⚙️ Настройки</h3>
                        <button class="btn btn-secondary" onclick="AuthService.logout()">
                            🚪 Выйти из аккаунта
                        </button>
                    </div>
                </div>
            </div>
        `;
    }
}

// Main App Class
class App {
    static async init() {
        utils.log('Initializing DX Project Mobile App');
        
        // Wait for device ready
        if (window.cordova) {
            document.addEventListener('deviceready', () => this.onDeviceReady(), false);
        } else {
            // Web version
            document.addEventListener('DOMContentLoaded', () => this.onDeviceReady());
        }
    }
    
    static async onDeviceReady() {
        utils.log('Device ready');
        
        // Initialize components
        this.initializeEventListeners();
        this.initializeNetworkStatus();
        
        // Show splash screen
        await this.showSplashScreen();
        
        // Load stored authentication
        const hasStoredAuth = await AuthService.loadStoredAuth();
        
        if (hasStoredAuth) {
            // User is already authenticated
            this.showApp();
            this.showScreen('main');
        } else {
            // Show auth screen
            this.showApp();
            this.showScreen('auth');
        }
        
        // Load initial data
        await this.loadInitialData();
        
        utils.log('App initialized successfully');
    }
    
    static async showSplashScreen() {
        return new Promise((resolve) => {
            setTimeout(() => {
                const splashScreen = document.getElementById('splash-screen');
                splashScreen.style.display = 'none';
                resolve();
            }, 2000);
        });
    }
    
    static showApp() {
        const app = document.getElementById('app');
        app.style.display = 'flex';
    }
    
    static showScreen(screenName) {
        if (screenName !== 'auth' && !appState.isAuthenticated) {
            this.showScreen('auth');
            return;
        }
        
        // Show/hide UI elements based on auth state
        const header = document.getElementById('app-header');
        const bottomNav = document.getElementById('bottom-nav');
        
        if (screenName === 'auth') {
            header.style.display = 'none';
            bottomNav.style.display = 'none';
        } else {
            header.style.display = 'block';
            bottomNav.style.display = 'flex';
        }
        
        ScreenManager.showScreen(screenName);
    }
    
    static initializeEventListeners() {
        // Menu toggle
        document.getElementById('menu-btn').addEventListener('click', () => {
            document.getElementById('side-menu').classList.add('active');
        });
        
        // Menu close
        document.getElementById('menu-close-btn').addEventListener('click', () => {
            document.getElementById('side-menu').classList.remove('active');
        });
        
        // Menu overlay close
        document.querySelector('.menu-overlay').addEventListener('click', () => {
            document.getElementById('side-menu').classList.remove('active');
        });
        
        // Menu navigation
        document.querySelectorAll('.menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.dataset.page;
                document.getElementById('side-menu').classList.remove('active');
                this.showScreen(page);
            });
        });
        
        // Bottom navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.dataset.page;
                this.showScreen(page);
            });
        });
        
        // Auth tabs
        document.querySelectorAll('.auth-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                this.switchAuthTab(tabName);
            });
        });
        
        // Auth forms
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin(e);
        });
        
        document.getElementById('register-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister(e);
        });
        
        // Steam login
        document.getElementById('steam-login-btn').addEventListener('click', () => {
            AuthService.loginWithSteam();
        });
        
        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => {
            AuthService.logout();
        });
        
        // Handle hardware back button
        if (window.cordova) {
            document.addEventListener('backbutton', (e) => {
                this.handleBackButton(e);
            }, false);
        }
    }
    
    static switchAuthTab(tabName) {
        // Switch tab buttons
        document.querySelectorAll('.auth-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Switch forms
        document.querySelectorAll('.auth-form').forEach(form => {
            form.classList.remove('active');
        });
        document.getElementById(`${tabName}-form`).classList.add('active');
    }
    
    static async handleLogin(event) {
        const formData = new FormData(event.target);
        const email = formData.get('email');
        const password = formData.get('password');
        
        try {
            await AuthService.login(email, password);
            Toast.success('Добро пожаловать!');
            this.showScreen('main');
        } catch (error) {
            Toast.error(error.message);
        }
    }
    
    static async handleRegister(event) {
        const formData = new FormData(event.target);
        const name = formData.get('name');
        const email = formData.get('email');
        const password = formData.get('password');
        const confirmPassword = formData.get('confirm_password');
        
        try {
            await AuthService.register(name, email, password, confirmPassword);
            Toast.success('Регистрация успешна! Добро пожаловать!');
            this.showScreen('main');
        } catch (error) {
            Toast.error(error.message);
        }
    }
    
    static handleBackButton(event) {
        event.preventDefault();
        
        // Close side menu if open
        const sideMenu = document.getElementById('side-menu');
        if (sideMenu.classList.contains('active')) {
            sideMenu.classList.remove('active');
            return;
        }
        
        // Close modals if open
        const openModal = document.querySelector('.modal.show');
        if (openModal) {
            openModal.classList.remove('show');
            return;
        }
        
        // Navigate back or exit app
        if (appState.currentPage === 'main' || appState.currentPage === 'auth') {
            if (navigator.app) {
                navigator.app.exitApp();
            }
        } else {
            this.showScreen('main');
        }
    }
    
    static initializeNetworkStatus() {
        if (window.Connection) {
            document.addEventListener('online', () => {
                Toast.success('Соединение восстановлено');
                this.syncOfflineData();
            });
            
            document.addEventListener('offline', () => {
                Toast.warning('Нет соединения с интернетом');
            });
        }
    }
    
    static async loadInitialData() {
        try {
            // Load data in background
            await Promise.all([
                DataService.loadServers().catch(e => utils.error('Failed to load servers', e)),
                DataService.loadNews().catch(e => utils.error('Failed to load news', e)),
                DataService.loadPrivileges().catch(e => utils.error('Failed to load privileges', e))
            ]);
            
            utils.log('Initial data loaded');
        } catch (error) {
            utils.error('Failed to load initial data', error);
        }
    }
    
    static async syncOfflineData() {
        // Sync any offline changes when connection is restored
        utils.log('Syncing offline data');
        await this.loadInitialData();
    }
    
    static showTopUpModal() {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3 class="modal-title">💰 Пополнение баланса</h3>
                    <button class="modal-close">&times;</button>
                </div>
                <form id="topup-form">
                    <div class="form-group">
                        <label>Сумма (₽)</label>
                        <input type="number" name="amount" min="10" step="1" required>
                    </div>
                    <div class="form-group">
                        <label>Способ оплаты</label>
                        <select name="method" required>
                            <option value="yoomoney">ЮMoney</option>
                            <option value="card">Банковская карта</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary">Пополнить</button>
                </form>
            </div>
        `;
        
        document.getElementById('modals-container').appendChild(modal);
        
        // Show modal
        setTimeout(() => modal.classList.add('show'), 100);
        
        // Handle form submit
        modal.querySelector('#topup-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const amount = parseFloat(formData.get('amount'));
            
            try {
                await PaymentService.processYooMoneyPayment(amount);
                modal.classList.remove('show');
                setTimeout(() => modal.remove(), 300);
            } catch (error) {
                Toast.error(error.message);
            }
        });
        
        // Handle close
        modal.querySelector('.modal-close').addEventListener('click', () => {
            modal.classList.remove('show');
            setTimeout(() => modal.remove(), 300);
        });
        
        // Handle overlay click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('show');
                setTimeout(() => modal.remove(), 300);
            }
        });
    }
}

// Global error handler
window.addEventListener('error', (event) => {
    utils.error('Global error', event.error);
    Toast.error('Произошла неожиданная ошибка');
});

// Initialize app
App.init();

// Export for global access
window.App = App;
window.AuthService = AuthService;
window.PaymentService = PaymentService;
window.DataService = DataService;
window.ScreenManager = ScreenManager;
window.Toast = Toast;