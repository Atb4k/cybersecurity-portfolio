(() => {
  'use strict';
  const root = document.documentElement;
  const toggleTheme = document.getElementById('theme-toggle');
  const toggleMenu = document.getElementById('mobile-menu-toggle');
  const navLinks = document.getElementById('primary-links');
  const progress = document.getElementById('scroll-progress-fill');
  const header = document.querySelector('.site-header');
  const sections = [...document.querySelectorAll('main section[id]')];
  const menuItems = [...document.querySelectorAll('.nav-link')];
  const themeMeta = document.querySelector('meta[name="theme-color"]');

  function getStoredTheme() {
    try { return localStorage.getItem('atb4k-theme'); } catch { return null; }
  }
  function storeTheme(mode) {
    try { localStorage.setItem('atb4k-theme', mode); } catch { /* storage unavailable */ }
  }
  function setTheme(mode, persist = false) {
    root.dataset.theme = mode;
    toggleTheme?.setAttribute('aria-label', mode === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    toggleTheme?.setAttribute('title', mode === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    if (themeMeta) themeMeta.setAttribute('content', mode === 'dark' ? '#08111e' : '#f5f8f8');
    if (persist) storeTheme(mode);
  }
  const storedTheme = getStoredTheme();
  const systemDark = matchMedia('(prefers-color-scheme: dark)').matches;
  setTheme(storedTheme === 'dark' || storedTheme === 'light' ? storedTheme : (systemDark ? 'dark' : 'light'));
  toggleTheme?.addEventListener('click', () => setTheme(root.dataset.theme === 'dark' ? 'light' : 'dark', true));

  function closeMenu() {
    navLinks?.classList.remove('nav-open');
    toggleMenu?.setAttribute('aria-expanded', 'false');
    toggleMenu?.setAttribute('aria-label', 'Open navigation menu');
  }
  toggleMenu?.addEventListener('click', () => {
    const isOpen = navLinks?.classList.toggle('nav-open');
    toggleMenu.setAttribute('aria-expanded', String(Boolean(isOpen)));
    toggleMenu.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
  });
  menuItems.forEach(link => link.addEventListener('click', closeMenu));
  document.addEventListener('keydown', event => { if (event.key === 'Escape') closeMenu(); });
  document.addEventListener('click', event => {
    if (navLinks?.classList.contains('nav-open') && !navLinks.contains(event.target) && !toggleMenu?.contains(event.target)) closeMenu();
  });

  function updateScroll() {
    const max = document.documentElement.scrollHeight - innerHeight;
    if (progress) progress.style.width = `${max > 0 ? Math.min(100, Math.max(0, scrollY / max * 100)) : 0}%`;
    header?.classList.toggle('is-scrolled', scrollY > 20);
    let activeId = '';
    for (const section of sections) {
      if (section.getBoundingClientRect().top < Math.max(170, innerHeight * 0.3)) activeId = section.id;
    }
    for (const link of menuItems) {
      const active = link.getAttribute('href') === `#${activeId}`;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    }
  }
  let ticking = false;
  addEventListener('scroll', () => {
    if (!ticking) {
      requestAnimationFrame(() => { updateScroll(); ticking = false; });
      ticking = true;
    }
  }, { passive: true });
  addEventListener('resize', updateScroll, { passive: true });
  updateScroll();
})();