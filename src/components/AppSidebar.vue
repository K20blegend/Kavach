<template>
  <!-- sidebar on the left side -->
  <aside class="my-sidebar">
    <!-- logo at top, boss said NO text just logo -->
    <div class="logo-box">
      <router-link to="/">
        <div class="logo-circle">
          <img src="/logo.png" alt="logo" class="logo-pic" />
        </div>
      </router-link>
    </div>

    <!-- navigation buttons -->
    <div class="nav-stuff">
      <router-link to="/" class="nav-btn" :class="{ active: $route.path === '/' || $route.path === '/results' }">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
        <span class="btn-text">Scanner</span>
      </router-link>

      <router-link to="/messages" class="nav-btn" :class="{ active: $route.path === '/messages' }">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          <path d="M8 10h.01M12 10h.01M16 10h.01"/>
        </svg>
        <span class="btn-text">Messages</span>
      </router-link>

      <router-link to="/simulator" class="nav-btn" :class="{ active: $route.path === '/simulator' }">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2">
          <rect width="20" height="16" x="2" y="4" rx="3"/>
          <path d="M6 8h.01M10 8h.01M14 8h.01"/>
          <path d="m10 13-2 2 2 2M14 13l2 2-2 2"/>
        </svg>
        <span class="btn-text">Simulator</span>
      </router-link>
    </div>

    <!-- removed the green dot here like requested -->
    <div class="empty-bottom">
      <!-- empty for now -->
    </div>
  </aside>
</template>

<script setup>
// sidebar doesn't need much logic, router handles active links
</script>

<style scoped>
/* sidebar styles */
.my-sidebar {
  position: fixed;
  left: 0;
  top: 0;
  bottom: 0;
  width: 80px;
  background: #09090b;
  border-right: 1px solid rgba(255, 255, 255, 0.08);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: space-between;
  padding: 20px 0;
  z-index: 999;
}

.logo-box {
  margin-top: 5px;
}

.logo-circle {
  width: 46px;
  height: 46px;
  background: white;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 5px;
  cursor: pointer;
}

.logo-circle:hover {
  transform: scale(1.05);
  box-shadow: 0 0 15px rgba(236, 72, 153, 0.5);
}

.logo-pic {
  width: 100%;
  height: 100%;
  object-fit: contain;
}

.nav-stuff {
  display: flex;
  flex-direction: column;
  gap: 15px;
  width: 100%;
  align-items: center;
}

.nav-btn {
  width: 60px;
  height: 60px;
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  color: #94a3b8;
  text-decoration: none;
  font-size: 11px;
  transition: 0.2s;
}

.nav-btn:hover {
  color: white;
  background: rgba(255, 255, 255, 0.05);
}

/* pink highlight when active */
.nav-btn.active {
  color: white;
  background: rgba(236, 72, 153, 0.15);
  border: 1px solid #ec4899;
}

.nav-btn.active svg {
  color: #ec4899;
}

.btn-text {
  font-weight: 600;
}

.empty-bottom {
  height: 40px;
}

/* mobile layout */
@media (max-width: 768px) {
  .my-sidebar {
    top: auto;
    bottom: 0;
    width: 100%;
    height: 65px;
    flex-direction: row;
    padding: 0 20px;
    border-right: none;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
  }

  .nav-stuff {
    flex-direction: row;
    width: auto;
  }

  .empty-bottom {
    display: none;
  }
}
</style>
