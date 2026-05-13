

'use strict';


function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}


function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}


function initLazyLoading() {
  if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          if (img.dataset.src) {
            img.src = img.dataset.src;
            img.classList.add('loaded');
            observer.unobserve(img);
          }
        }
      });
    }, {
      rootMargin: '50px'
    });

    document.querySelectorAll('img[data-src]').forEach(img => {
      imageObserver.observe(img);
    });
  }
}


function smoothScrollTo(element, offset = 0) {
  const targetPosition = element.getBoundingClientRect().top + window.pageYOffset - offset;
  window.scrollTo({
    top: targetPosition,
    behavior: 'smooth'
  });
}


function createRipple(event) {
  const button = event.currentTarget;
  const ripple = document.createElement('span');
  const diameter = Math.max(button.clientWidth, button.clientHeight);
  const radius = diameter / 2;

  ripple.style.width = ripple.style.height = `${diameter}px`;
  ripple.style.left = `${event.clientX - button.offsetLeft - radius}px`;
  ripple.style.top = `${event.clientY - button.offsetTop - radius}px`;
  ripple.classList.add('ripple-effect');

  const existingRipple = button.querySelector('.ripple-effect');
  if (existingRipple) {
    existingRipple.remove();
  }

  button.appendChild(ripple);

  setTimeout(() => ripple.remove(), 600);
}


const toastQueue = [];
let isShowingToast = false;

function showEnhancedToast(message, type = 'info', duration = 4000) {
  toastQueue.push({ message, type, duration });
  if (!isShowingToast) {
    processToastQueue();
  }
}

function processToastQueue() {
  if (toastQueue.length === 0) {
    isShowingToast = false;
    return;
  }

  isShowingToast = true;
  const { message, type, duration } = toastQueue.shift();
  
  const container = document.getElementById('wpvs-toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `wpvs-toast ${type}`;
  toast.textContent = message;
  toast.style.opacity = '0';
  toast.style.transform = 'translateX(20px)';
  
  container.appendChild(toast);
  requestAnimationFrame(() => {
    toast.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
    toast.style.opacity = '1';
    toast.style.transform = 'translateX(0)';
  });
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    setTimeout(() => {
      toast.remove();
      processToastQueue();
    }, 300);
  }, duration);
}


async function copyToClipboardEnhanced(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const originalText = button.textContent;
    const originalHTML = button.innerHTML;
    
    button.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copiado';
    button.style.background = 'var(--green-dim)';
    button.style.color = 'var(--green)';
    button.style.borderColor = 'rgba(0,214,143,.35)';
    
    setTimeout(() => {
      button.innerHTML = originalHTML;
      button.style.background = '';
      button.style.color = '';
      button.style.borderColor = '';
    }, 2000);
    
    showEnhancedToast('Copiado al portapapeles', 'ok', 2000);
  } catch (err) {
    showEnhancedToast('Error al copiar', 'err', 3000);
  }
}


function setupUrlValidation() {
  const urlInput = document.getElementById('urlInput');
  const urlWrap = document.getElementById('urlWrap');
  
  if (!urlInput || !urlWrap) return;

  const validateUrl = debounce((value) => {
    if (!value.trim()) {
      urlWrap.classList.remove('url-valid', 'url-invalid');
      return;
    }

    const isValid = isValidUrl(value);
    urlWrap.classList.toggle('url-valid', isValid);
    urlWrap.classList.toggle('url-invalid', !isValid);
  }, 300);

  urlInput.addEventListener('input', (e) => validateUrl(e.target.value));
}


function animateNumber(element, start, end, duration = 1000) {
  const range = end - start;
  const increment = range / (duration / 16);
  let current = start;

  const timer = setInterval(() => {
    current += increment;
    if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
      current = end;
      clearInterval(timer);
    }
    element.textContent = Math.round(current);
    element.classList.add('animating');
    setTimeout(() => element.classList.remove('animating'), 60);
  }, 16);
}


function initScrollAnimations() {
  if (!('IntersectionObserver' in window)) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  });

  document.querySelectorAll('.animate-on-scroll').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
    observer.observe(el);
  });
}


function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      const searchInput = document.getElementById('vulnSearch') || 
                         document.getElementById('histSearch') ||
                         document.getElementById('urlInput');
      if (searchInput) {
        searchInput.focus();
        searchInput.select();
      }
    }
    if (e.key === 'Escape') {
      const modal = document.querySelector('.modal-overlay[style*="display: flex"]');
      if (modal) {
        modal.style.display = 'none';
      }
      const mapOverlay = document.getElementById('mapOverlay');
      if (mapOverlay && mapOverlay.classList.contains('open')) {
        mapOverlay.classList.remove('open');
      }
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const scanBtn = document.getElementById('scanBtn');
      if (scanBtn && !scanBtn.disabled) {
        scanBtn.click();
      }
    }
  });
}


function detectSystemTheme() {
  if (!window.matchMedia) return;

  const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
  
  function handleThemeChange(e) {
    const currentTheme = localStorage.getItem('wpvs_theme');
    if (!currentTheme) {
      document.documentElement.classList.toggle('light', !e.matches);
    }
  }

  darkModeQuery.addEventListener('change', handleThemeChange);
  if (!localStorage.getItem('wpvs_theme')) {
    document.documentElement.classList.toggle('light', !darkModeQuery.matches);
  }
}


function preloadCriticalResources() {
  const criticalResources = [
    '/static/logo.png',
    '/api/db-status'
  ];

  criticalResources.forEach(resource => {
    if (resource.startsWith('/api/')) {
      fetch(resource, { method: 'HEAD' }).catch(() => {});
    } else {
      const link = document.createElement('link');
      link.rel = 'preload';
      link.as = resource.endsWith('.png') ? 'image' : 'fetch';
      link.href = resource;
      document.head.appendChild(link);
    }
  });
}


function setLoadingState(button, isLoading) {
  if (isLoading) {
    button.classList.add('loading');
    button.disabled = true;
    button.dataset.originalText = button.textContent;
  } else {
    button.classList.remove('loading');
    button.disabled = false;
    if (button.dataset.originalText) {
      button.textContent = button.dataset.originalText;
    }
  }
}


function initTooltips() {
  document.querySelectorAll('[title]').forEach(el => {
    const title = el.getAttribute('title');
    if (title) {
      el.setAttribute('data-tooltip', title);
      el.removeAttribute('title');
    }
  });
}


function monitorConnection() {
  if (!('connection' in navigator)) return;

  function updateConnectionStatus() {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (connection) {
      const effectiveType = connection.effectiveType;
      if (effectiveType === 'slow-2g' || effectiveType === '2g') {
        showEnhancedToast('Conexión lenta detectada. Algunas funciones pueden tardar más.', 'warn', 5000);
      }
    }
  }

  window.addEventListener('online', () => {
    showEnhancedToast('Conexión restaurada', 'ok', 3000);
  });

  window.addEventListener('offline', () => {
    showEnhancedToast('Sin conexión a Internet', 'err', 5000);
  });

  updateConnectionStatus();
}


function logPerformanceMetrics() {
  if (!window.performance || !window.performance.timing) return;

  window.addEventListener('load', () => {
    setTimeout(() => {
      const perfData = window.performance.timing;
      const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
      const connectTime = perfData.responseEnd - perfData.requestStart;
      const renderTime = perfData.domComplete - perfData.domLoading;

      console.log('📊 Performance Metrics:');
      console.log(`  Page Load: ${pageLoadTime}ms`);
      console.log(`  Server Response: ${connectTime}ms`);
      console.log(`  DOM Render: ${renderTime}ms`);
      if (pageLoadTime > 5000) {
        console.warn('⚠️ Página cargando lentamente. Considera optimizar recursos.');
      }
    }, 0);
  });
}


function trapFocus(element) {
  const focusableElements = element.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  const firstFocusable = focusableElements[0];
  const lastFocusable = focusableElements[focusableElements.length - 1];

  element.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;

    if (e.shiftKey) {
      if (document.activeElement === firstFocusable) {
        lastFocusable.focus();
        e.preventDefault();
      }
    } else {
      if (document.activeElement === lastFocusable) {
        firstFocusable.focus();
        e.preventDefault();
      }
    }
  });

  firstFocusable?.focus();
}


function animateCardsOnLoad() {
  const cards = document.querySelectorAll('.vuln-card, .comp-card, .history-row');
  cards.forEach((card, index) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(10px)';
    
    setTimeout(() => {
      card.style.transition = 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
      card.style.opacity = '1';
      card.style.transform = 'translateY(0)';
    }, index * 50);
  });
}


function initUXEnhancements() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  function init() {
    console.log('🚀 Inicializando mejoras UX...');
    initLazyLoading();
    setupUrlValidation();
    initScrollAnimations();
    initKeyboardShortcuts();
    detectSystemTheme();
    preloadCriticalResources();
    initTooltips();
    monitorConnection();
    logPerformanceMetrics();
    document.querySelectorAll('.btn, .btn-scan, button').forEach(button => {
      button.addEventListener('click', createRipple);
    });
    document.querySelectorAll('.modal-overlay').forEach(modal => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.style.display = 'none';
        }
      });
    });
    const riskNum = document.getElementById('riskNum');
    if (riskNum && riskNum.textContent !== '—') {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const value = parseInt(riskNum.textContent);
            if (!isNaN(value)) {
              animateNumber(riskNum, 0, value, 1500);
              observer.unobserve(entry.target);
            }
          }
        });
      });
      observer.observe(riskNum);
    }

    console.log('✅ Mejoras UX inicializadas correctamente');
  }
}
initUXEnhancements();
window.UXEnhancements = {
  showToast: showEnhancedToast,
  copyToClipboard: copyToClipboardEnhanced,
  smoothScrollTo,
  animateNumber,
  setLoadingState,
  debounce,
  throttle
};
