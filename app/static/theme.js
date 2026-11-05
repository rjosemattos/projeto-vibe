/* Applies the saved theme before first paint (external file: the CSP forbids inline scripts). */
(function () {
    try {
        var saved = localStorage.getItem("ps-theme");
        if (saved === "light" || saved === "dark") {
            document.documentElement.setAttribute("data-theme", saved);
        }
    } catch (e) { /* storage unavailable: follow the system theme */ }
})();
