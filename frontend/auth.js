// auth.js
const API_BASE = "";

function getToken() {
    return localStorage.getItem("token");
}

function setToken(token) {
    localStorage.setItem("token", token);
}

function removeToken() {
    localStorage.removeItem("token");
}

function checkAuth(redirectIfMissing = true) {
    const token = getToken();
    if (!token && redirectIfMissing) {
        window.location.href = "/static/login.html";
        return false;
    }
    return true;
}

function logout() {
    removeToken();
    window.location.href = "/static/login.html";
}

async function authenticatedFetch(url, options = {}) {
    const token = getToken();
    if (!token) {
        window.location.href = "/static/login.html";
        return null;
    }

    const headers = options.headers || {};
    headers["Authorization"] = `Bearer ${token}`;
    options.headers = headers;

    const response = await fetch(url, options);
    if (response.status === 401) {
        // Token expired
        logout();
        return null;
    }
    return response;
}
