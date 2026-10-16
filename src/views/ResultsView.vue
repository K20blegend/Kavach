<template>
  <div class="results-wrapper">

    <!-- top nav -->
    <div class="top-nav">
      <router-link to="/" class="back-link">
        ← Back to Scanner
      </router-link>

      <div class="scan-bar">
        <span class="bar-label">Target:</span>
        <input 
          v-model="inputUrl" 
          class="target-input" 
          placeholder="https://example.com" 
          @keyup.enter="startScan"
        />
        <button class="recheck-btn" :disabled="loading" @click="startScan">
          {{ loading ? 'Scanning...' : 'Scan' }}
        </button>
      </div>
    </div>

    <!-- loading indicator -->
    <div v-if="loading" class="state-box">
      <div class="spinner"></div>
      <p>Running live security audit on {{ inputUrl }}...</p>
    </div>

    <!-- error message -->
    <div v-else-if="error" class="state-box error-box">
      <span class="err-icon">⚠️</span>
      <p>{{ error }}</p>
      <button class="retry-btn" @click="startScan">Retry</button>
    </div>

    <!-- results layout -->
    <div v-else-if="result" class="results-layout">

      <!-- LEFT: trust score gauge & bars -->
      <div class="left-panel">
        
        <div class="glass-box score-card">
          <h3 class="panel-heading">Overall Trust Score</h3>
          <p class="panel-sub">Calculated by Kavach security engine</p>

          <div class="gauge-wrap">
            <svg class="gauge-svg" viewBox="0 0 160 160">
              <circle cx="80" cy="80" r="64" class="gauge-bg" />
              <circle
                cx="80"
                cy="80"
                r="64"
                class="gauge-bar"
                :stroke="scoreColor"
                :stroke-dasharray="circumference"
                :stroke-dashoffset="dashOffset"
              />
            </svg>
            <div class="gauge-text">
              <span class="score-num">{{ trustScore.toFixed(1) }}</span>
              <span class="score-max">/ 10</span>
            </div>
          </div>

          <div class="verdict-tag" :style="{ color: scoreColor, background: scoreBg }">
            {{ verdictLabel }}
          </div>
        </div>

        <!-- breakdown progress bars -->
        <div class="glass-box breakdown-card">
          <h3 class="panel-heading">Checks Coverage</h3>
          <p class="panel-sub">{{ result.coverage?.completed || 0 }} of {{ result.coverage?.total || 6 }} completed</p>

          <div class="bar-item" v-for="chk in result.checks" :key="chk.name">
            <div class="bar-labels">
              <span>{{ formatCheckName(chk.name) }}</span>
              <span class="badge" :class="'badge-' + chk.status">{{ chk.status }}</span>
            </div>
            <div class="bar-track">
              <div 
                class="bar-fill" 
                :style="{ 
                  width: chk.status === 'pass' ? '100%' : chk.status === 'warn' ? '60%' : chk.status === 'fail' ? '25%' : '45%',
                  background: chk.status === 'pass' ? '#22c55e' : chk.status === 'warn' ? '#eab308' : chk.status === 'fail' ? '#ec4899' : '#64748b' 
                }"
              ></div>
            </div>
          </div>
        </div>

        <!-- recommendations -->
        <div v-if="result.recommendations?.length" class="glass-box recs-card">
          <h3 class="panel-heading">Recommendations</h3>
          <ul class="recs-list">
            <li v-for="(rec, i) in result.recommendations" :key="i">{{ rec }}</li>
          </ul>
        </div>

      </div>

      <!-- RIGHT: detailed check cards -->
      <div class="right-panel">

        <!-- 1. DNS check -->
        <div class="glass-box check-box" v-if="getCheck('dns')">
          <div class="chk-top">
            <div class="chk-title">
              <span class="chk-icon">🌐</span>
              <h4>Public DNS Resolution</h4>
            </div>
            <span class="status-pill" :class="'pill-' + getCheck('dns').status">
              {{ getCheck('dns').status }}
            </span>
          </div>
          <p class="chk-summary">{{ getCheck('dns').summary }}</p>
          <div class="info-grid">
            <div class="info-row">
              <span class="lbl">Resolved IPs:</span>
              <span class="val">{{ getCheck('dns').evidence?.addresses?.join(', ') || 'None' }}</span>
            </div>
          </div>
        </div>

        <!-- 2. DNSBL -->
        <div class="glass-box check-box" v-if="getCheck('dnsbl')">
          <div class="chk-top">
            <div class="chk-title">
              <span class="chk-icon">📡</span>
              <h4>DNS Blacklists (DNSBL)</h4>
            </div>
            <span class="status-pill" :class="'pill-' + getCheck('dnsbl').status">
              {{ getCheck('dnsbl').status }}
            </span>
          </div>
          <p class="chk-summary">{{ getCheck('dnsbl').summary }}</p>
          <div class="info-grid">
            <div class="info-row">
              <span class="lbl">Blacklist Status:</span>
              <span class="val">{{ getCheck('dnsbl').status === 'pass' ? 'Clean' : getCheck('dnsbl').status }}</span>
            </div>
          </div>
        </div>

        <!-- 3. Domain Age -->
        <div class="glass-box check-box" v-if="getCheck('domain_age')">
          <div class="chk-top">
            <div class="chk-title">
              <span class="chk-icon">📅</span>
              <h4>RDAP Domain Age</h4>
            </div>
            <span class="status-pill" :class="'pill-' + getCheck('domain_age').status">
              {{ getCheck('domain_age').status }}
            </span>
          </div>
          <p class="chk-summary">{{ getCheck('domain_age').summary }}</p>
          <div class="info-grid">
            <div class="info-row">
              <span class="lbl">Registered Domain:</span>
              <span class="val">{{ getCheck('domain_age').evidence?.registered_domain || 'N/A' }}</span>
            </div>
            <div class="info-row">
              <span class="lbl">Age in Days:</span>
              <span class="val">{{ getCheck('domain_age').evidence?.age_days !== undefined ? getCheck('domain_age').evidence?.age_days + ' days' : 'Unknown' }}</span>
            </div>
            <div class="info-row">
              <span class="lbl">Registration Date:</span>
              <span class="val">{{ getCheck('domain_age').evidence?.registration_date || 'N/A' }}</span>
            </div>
          </div>
        </div>

        <!-- 4. SSL/TLS -->
        <div class="glass-box check-box" v-if="getCheck('tls')">
          <div class="chk-top">
            <div class="chk-title">
              <span class="chk-icon">🔒</span>
              <h4>SSL / TLS Inspection</h4>
            </div>
            <span class="status-pill" :class="'pill-' + getCheck('tls').status">
              {{ getCheck('tls').status }}
            </span>
          </div>
          <p class="chk-summary">{{ getCheck('tls').summary }}</p>
          <div class="info-grid">
            <div class="info-row">
              <span class="lbl">Protocol:</span>
              <span class="val">{{ getCheck('tls').evidence?.protocol || 'N/A' }}</span>
            </div>
            <div class="info-row">
              <span class="lbl">Expires In:</span>
              <span class="val">{{ getCheck('tls').evidence?.days_remaining !== undefined ? getCheck('tls').evidence?.days_remaining + ' days' : 'N/A' }}</span>
            </div>
            <div class="info-row">
              <span class="lbl">Issuer:</span>
              <span class="val truncate">{{ getCheck('tls').evidence?.issuer || 'N/A' }}</span>
            </div>
          </div>
        </div>

        <!-- 5. Homograph / Typosquatting -->
        <div class="glass-box check-box" v-if="getCheck('hostname')">
          <div class="chk-top">
            <div class="chk-title">
              <span class="chk-icon">🔤</span>
              <h4>Homograph & Typosquatting</h4>
            </div>
            <span class="status-pill" :class="'pill-' + getCheck('hostname').status">
              {{ getCheck('hostname').status }}
            </span>
          </div>
          <p class="chk-summary">{{ getCheck('hostname').summary }}</p>
          <div class="info-grid">
            <div class="info-row">
              <span class="lbl">Unicode Domain:</span>
              <span class="val">{{ getCheck('hostname').evidence?.unicode_hostname || 'N/A' }}</span>
            </div>
            <div class="info-row" v-if="getCheck('hostname').evidence?.brand_matches?.length">
              <span class="lbl">Brand Lookalike:</span>
              <span class="val highlight">Matches {{ getCheck('hostname').evidence.brand_matches[0]?.brand }} (distance: {{ getCheck('hostname').evidence.brand_matches[0]?.edit_distance }})</span>
            </div>
            <div class="info-row" v-if="getCheck('hostname').evidence?.mixed_scripts?.length">
              <span class="lbl">Mixed Alphabets:</span>
              <span class="val highlight">{{ getCheck('hostname').evidence.mixed_scripts.join(', ') }}</span>
            </div>
          </div>
        </div>

        <!-- 6. HTTP & Downgrade -->
        <div class="glass-box check-box" v-if="getCheck('http')">
          <div class="chk-top">
            <div class="chk-title">
              <span class="chk-icon">🛡️</span>
              <h4>HTTP Security & Redirects</h4>
            </div>
            <span class="status-pill" :class="'pill-' + getCheck('http').status">
              {{ getCheck('http').status }}
            </span>
          </div>
          <p class="chk-summary">{{ getCheck('http').summary }}</p>
          <div class="info-grid">
            <div class="info-row">
              <span class="lbl">Status Code:</span>
              <span class="val">{{ getCheck('http').evidence?.status_code || 200 }}</span>
            </div>
            <div class="info-row" v-if="getCheck('http').evidence?.redirect_chain?.length">
              <span class="lbl">Redirects:</span>
              <span class="val">{{ getCheck('http').evidence.redirect_chain.length }} hops</span>
            </div>
          </div>
        </div>

      </div>

    </div>

  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { auditUrl } from '../services/api'

const route = useRoute()

const inputUrl = ref(route.query.url || 'https://example.com')
const loading = ref(false)
const error = ref('')
const result = ref(null)

const circumference = 2 * Math.PI * 64

const trustScore = computed(() => {
  return result.value?.trust_score ?? 0
})

const dashOffset = computed(() => {
  const val = Math.min(Math.max(trustScore.value, 0), 10)
  return circumference - (val / 10) * circumference
})

const scoreColor = computed(() => {
  if (trustScore.value >= 7) return '#22c55e'
  if (trustScore.value >= 4) return '#eab308'
  return '#ec4899'
})

const scoreBg = computed(() => {
  if (trustScore.value >= 7) return 'rgba(34, 197, 94, 0.15)'
  if (trustScore.value >= 4) return 'rgba(234, 179, 8, 0.15)'
  return 'rgba(236, 72, 153, 0.15)'
})

const verdictLabel = computed(() => {
  const v = result.value?.verdict
  if (v === 'low_risk') return 'Low Risk / Clean'
  if (v === 'caution') return 'Caution Advised'
  if (v === 'high_risk') return 'High Risk Threat'
  return 'Unknown Status'
})

function getCheck(name) {
  return result.value?.checks?.find(c => c.name === name)
}

function formatCheckName(name) {
  const map = {
    dns: 'DNS Resolution',
    dnsbl: 'DNS Blacklist',
    domain_age: 'Domain Age (RDAP)',
    tls: 'SSL / TLS Certificate',
    hostname: 'Homograph Distance',
    http: 'HTTP / Redirects'
  }
  return map[name] || name
}

async function startScan() {
  if (!inputUrl.value.trim()) return
  loading.value = true
  error.value = ''

  try {
    const data = await auditUrl(inputUrl.value.trim())
    result.value = data.result
  } catch (err) {
    error.value = err.message || 'Failed to scan target'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  startScan()
})
</script>

<style scoped>
.results-wrapper {
  padding: 30px 24px 60px;
  max-width: 1240px;
  margin: 0 auto;
  width: 100%;
}

.top-nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 25px;
  flex-wrap: wrap;
  gap: 12px;
}

.back-link {
  color: #94a3b8;
  font-size: 13.5px;
  font-weight: 600;
  text-decoration: none;
  padding: 6px 14px;
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.back-link:hover {
  color: white;
  border-color: #ec4899;
}

.scan-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
  padding: 4px 6px 4px 14px;
  border-radius: 999px;
}

.bar-label {
  color: #64748b;
  font-size: 13px;
  font-weight: 600;
}

.target-input {
  background: transparent;
  border: none;
  color: white;
  font-size: 13.5px;
  font-weight: 600;
  outline: none;
  width: 240px;
}

.recheck-btn {
  background: #ec4899;
  color: white;
  border: none;
  padding: 6px 14px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}

.recheck-btn:disabled {
  opacity: 0.6;
}

/* state box for loading and error */
.state-box {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  padding: 50px 20px;
  text-align: center;
  color: #94a3b8;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 14px;
}

.spinner {
  width: 32px;
  height: 32px;
  border: 3px solid rgba(236, 72, 153, 0.2);
  border-top-color: #ec4899;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-box {
  border-color: rgba(239, 68, 68, 0.3);
  color: #f87171;
}

.err-icon {
  font-size: 28px;
}

.retry-btn {
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.2);
  color: white;
  padding: 6px 16px;
  border-radius: 8px;
  cursor: pointer;
}

/* main 2-column grid */
.results-layout {
  display: grid;
  grid-template-columns: 350px 1fr;
  gap: 24px;
  align-items: start;
}

.glass-box {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  padding: 20px;
}

.panel-heading {
  font-size: 15px;
  font-weight: 800;
  color: white;
  margin-bottom: 2px;
}

.panel-sub {
  font-size: 12px;
  color: #64748b;
  margin-bottom: 16px;
}

.left-panel {
  display: flex;
  flex-direction: column;
  gap: 18px;
  position: sticky;
  top: 20px;
}

.score-card {
  text-align: center;
}

.gauge-wrap {
  position: relative;
  width: 150px;
  height: 150px;
  margin: 0 auto 12px;
}

.gauge-svg {
  width: 100%;
  height: 100%;
  transform: rotate(-90deg);
}

.gauge-bg {
  fill: none;
  stroke: rgba(255, 255, 255, 0.06);
  stroke-width: 10;
}

.gauge-bar {
  fill: none;
  stroke-width: 10;
  stroke-linecap: round;
  transition: stroke-dashoffset 0.6s ease, stroke 0.4s ease;
}

.gauge-text {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.score-num {
  font-size: 34px;
  font-weight: 900;
  color: white;
}

.score-max {
  font-size: 12px;
  color: #64748b;
}

.verdict-tag {
  display: inline-block;
  padding: 5px 16px;
  border-radius: 999px;
  font-weight: 800;
  font-size: 12.5px;
}

/* progress bars */
.bar-item {
  margin-bottom: 12px;
}

.bar-labels {
  display: flex;
  justify-content: space-between;
  font-size: 11.5px;
  color: #94a3b8;
  margin-bottom: 4px;
}

.badge {
  font-size: 10px;
  font-weight: bold;
  text-transform: uppercase;
}
.badge-pass { color: #22c55e; }
.badge-warn { color: #eab308; }
.badge-fail { color: #ec4899; }
.badge-unknown { color: #94a3b8; }

.bar-track {
  width: 100%;
  height: 6px;
  background: rgba(255, 255, 255, 0.06);
  border-radius: 999px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  border-radius: 999px;
  transition: width 0.4s ease;
}

/* recommendations list */
.recs-card {
  border-left: 3px solid #eab308;
}

.recs-list {
  padding-left: 18px;
  font-size: 12px;
  color: #cbd5e1;
  line-height: 1.5;
}

.recs-list li {
  margin-bottom: 6px;
}

/* right panel checks */
.right-panel {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.check-box {
  border-left: 3px solid #ec4899;
}

.chk-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.chk-title {
  display: flex;
  align-items: center;
  gap: 8px;
}

.chk-icon {
  font-size: 18px;
}

.chk-title h4 {
  font-size: 14.5px;
  font-weight: 800;
  color: white;
}

.status-pill {
  font-size: 11px;
  font-weight: 800;
  padding: 3px 10px;
  border-radius: 999px;
  text-transform: uppercase;
}

.pill-pass {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}
.pill-warn {
  background: rgba(234, 179, 8, 0.15);
  color: #eab308;
}
.pill-fail {
  background: rgba(236, 72, 153, 0.2);
  color: #ec4899;
}
.pill-unknown {
  background: rgba(255, 255, 255, 0.08);
  color: #94a3b8;
}

.chk-summary {
  font-size: 12px;
  color: #94a3b8;
  margin-bottom: 10px;
}

.info-grid {
  display: flex;
  flex-direction: column;
  gap: 6px;
  background: rgba(0, 0, 0, 0.25);
  padding: 10px 14px;
  border-radius: 8px;
}

.info-row {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
}

.info-row .lbl {
  color: #64748b;
}

.info-row .val {
  color: #f1f5f9;
  font-weight: 600;
}

.info-row .val.highlight {
  color: #ec4899;
}

.truncate {
  max-width: 320px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

@media (max-width: 900px) {
  .results-layout {
    grid-template-columns: 1fr;
  }
  .left-panel {
    position: static;
  }
}
</style>
