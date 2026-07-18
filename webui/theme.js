(function () {
  "use strict";

  var storedTheme = localStorage.getItem("heteronetwork_theme");
  var theme = storedTheme === "dark" || storedTheme === "light"
    ? storedTheme
    : (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  var storedLocale = localStorage.getItem("heteronetwork_locale");
  var locale = storedLocale === "ja" || storedLocale === "en"
    ? storedLocale
    : (navigator.language.toLowerCase().indexOf("ja") === 0 ? "ja" : "en");

  document.documentElement.dataset.theme = theme;
  document.documentElement.lang = locale;
}());
