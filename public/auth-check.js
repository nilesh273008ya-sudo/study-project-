(async function() {
    try {
        const res = await fetch('/api/me', { credentials: 'include' });
        const data = await res.json();
        if (!data.success) {
            window.location.href = '/login.html';
        }
    } catch {
        window.location.href = '/login.html';
    }
})();
