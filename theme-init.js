(function () {
  try {
    var pref = localStorage.getItem('theme') || 'system';
    var dark = pref === 'dark' || (pref === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  } catch (e) {
    /* storage unavailable: keep the default theme */
  }
})();
