<template>
  <div class="simulator-page">
    <div class="content-wrapper">
      <!-- Page Header -->
      <div class="header-section">
        <div class="header-badge">
          <span class="badge-dot"></span>
          INTERACTIVE THREAT LAB
        </div>
        <h1 class="page-title">Security <span class="highlight">Simulator</span></h1>
        <p class="page-desc">
          Test your threat detection skills against live social engineering scenarios. Inspect simulated emails, SMS alerts, and browser screens to uncover evidence of fraud.
        </p>
      </div>

      <!-- Scenario Selector Controls -->
      <div class="selector-card glass-panel">
        <div class="selector-row">
          <div class="selector-item">
            <label class="control-label">Select Scenario</label>
            <select v-model="selectedScenarioId" class="scenario-select" @change="loadScenario(selectedScenarioId)">
              <option v-for="item in scenariosList" :key="item.id" :value="item.id">
                [{{ item.difficulty.toUpperCase() }}] {{ item.title }} ({{ item.channel.toUpperCase() }})
              </option>
            </select>
          </div>

          <div class="selector-item filter-group">
            <label class="control-label">Filter Channel</label>
            <div class="filter-chips">
              <button 
                type="button" 
                class="filter-chip" 
                :class="{ active: channelFilter === '' }"
                @click="setChannelFilter('')"
              >All</button>
              <button 
                type="button" 
                class="filter-chip" 
                :class="{ active: channelFilter === 'email' }"
                @click="setChannelFilter('email')"
              >Email</button>
              <button 
                type="button" 
                class="filter-chip" 
                :class="{ active: channelFilter === 'sms' }"
                @click="setChannelFilter('sms')"
              >SMS</button>
              <button 
                type="button" 
                class="filter-chip" 
                :class="{ active: channelFilter === 'browser' }"
                @click="setChannelFilter('browser')"
              >Browser</button>
              <button 
                type="button" 
                class="filter-chip" 
                :class="{ active: channelFilter === 'chat' }"
                @click="setChannelFilter('chat')"
              >Chat</button>
            </div>
          </div>
        </div>

        <!-- Scenario Context Info Banner -->
        <div v-if="scenario" class="scenario-info-banner">
          <div class="info-badges">
            <span class="diff-badge" :class="'diff-' + scenario.difficulty">
              {{ scenario.difficulty.toUpperCase() }}
            </span>
            <span class="channel-badge">{{ scenario.channel.toUpperCase() }}</span>
            <span class="xp-badge">★ Max {{ scenario.maximum_xp || 40 }} XP</span>
            <span class="time-badge">⏱ ~{{ scenario.estimated_minutes || 2 }} mins</span>
          </div>

          <div class="scenario-context-box">
            <div class="context-label">Mission Context:</div>
            <div class="context-text">{{ scenario.context }}</div>
          </div>
        </div>
      </div>

      <!-- Mock Virtual Device / Browser Window Container -->
      <div v-if="scenario" class="virtual-window glass-panel">
        <!-- Window Topbar -->
        <div class="window-topbar">
          <div class="window-dots">
            <span class="dot dot-close"></span>
            <span class="dot dot-min"></span>
            <span class="dot dot-expand"></span>
          </div>

          <!-- Virtual Address Bar -->
          <div class="address-bar">
            <span class="channel-icon">
              <svg v-if="scenario.channel === 'email'" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                <rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
              </svg>
              <svg v-else-if="scenario.channel === 'sms'" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
              </svg>
              <svg v-else viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20M2 12h20"/>
              </svg>
            </span>
            <span class="address-text">{{ getScenarioAddress(scenario) }}</span>
          </div>

          <div class="window-status">
            <span class="status-pill">Interactive Inspection Mode</span>
          </div>
        </div>

        <!-- Interactive Simulation Canvas -->
        <div class="interactive-canvas">
          <div class="instruction-bar">
            <span>Click on any element you believe provides <strong>evidence of fraud</strong>:</span>
            <span class="selected-counter">{{ selectedIds.length }} Flagged</span>
          </div>

          <!-- Clickable Elements Container -->
          <div class="elements-grid">
            <div 
              v-for="elem in scenario.elements" 
              :key="elem.id"
              class="interactive-elem"
              :class="{ 'flagged': selectedIds.includes(elem.id) }"
              @click="toggleElement(elem.id)"
            >
              <div class="elem-header">
                <span class="elem-type-label">{{ elem.label || elem.type }}</span>
                <span class="flag-indicator">
                  {{ selectedIds.includes(elem.id) ? 'FLAGGED AS THREAT' : 'CLICK TO FLAG' }}
                </span>
              </div>
              <div class="elem-body">
                <span class="elem-text">{{ elem.text }}</span>
              </div>
            </div>
          </div>

          <!-- Canvas Action Bar -->
          <div class="canvas-actions">
            <button 
              type="button" 
              class="clear-btn" 
              :disabled="selectedIds.length === 0 || evaluating" 
              @click="selectedIds = []"
            >
              Clear Selection
            </button>

            <button 
              type="button" 
              class="submit-btn" 
              :disabled="evaluating"
              @click="handleSubmit"
            >
              <span v-if="!evaluating">Submit Findings</span>
              <span v-else class="btn-spinner">Evaluating...</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Evaluation & Results Section -->
      <div v-if="evalResult" class="results-card glass-panel" :class="scoreClass">
        <div class="results-header">
          <div class="score-col">
            <div class="score-large">{{ evalResult.score }}%</div>
            <div class="score-sub">Scenario Accuracy Score</div>
          </div>
          <div class="xp-col">
            <div class="xp-badge-lg">+{{ evalResult.xp_earned }} XP</div>
            <div class="xp-max">out of {{ evalResult.maximum_xp }} XP</div>
          </div>
        </div>

        <!-- Stats breakdown row -->
        <div class="stats-row">
          <div class="stat-pill pill-correct">
            <span class="stat-num">{{ evalResult.correct_count }}</span>
            <span class="stat-text">Correct Catches</span>
          </div>
          <div class="stat-pill pill-missed">
            <span class="stat-num">{{ evalResult.missed_count }}</span>
            <span class="stat-text">Missed Threats</span>
          </div>
          <div class="stat-pill pill-fp">
            <span class="stat-num">{{ evalResult.false_positive_count }}</span>
            <span class="stat-text">False Alarms</span>
          </div>
        </div>

        <!-- Detailed Indicators Feedback -->
        <div class="feedback-section">
          <h3 class="feedback-title">Threat Breakdown & Explanations:</h3>
          <div class="indicator-feedback-list">
            <div 
              v-for="item in evalResult.indicators" 
              :key="item.id" 
              class="feedback-item"
              :class="item.selected ? 'item-hit' : 'item-miss'"
            >
              <div class="fb-top">
                <span class="fb-badge">{{ item.selected ? 'YOU CAUGHT THIS' : 'YOU MISSED THIS' }}</span>
                <span class="fb-label">{{ item.label }}</span>
              </div>
              <p class="fb-text">{{ item.explanation }}</p>
            </div>

            <!-- False Positives if any -->
            <div 
              v-for="fp in evalResult.false_positives" 
              :key="fp.id" 
              class="feedback-item item-fp"
            >
              <div class="fb-top">
                <span class="fb-badge">FALSE ALARM</span>
                <span class="fb-label">{{ fp.label }}</span>
              </div>
              <p class="fb-text">{{ fp.explanation }}</p>
            </div>
          </div>
        </div>

        <!-- Lesson takeaway -->
        <div v-if="evalResult.lesson" class="lesson-box">
          <div class="lesson-header">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
            </svg>
            Key Defense Takeaway
          </div>
          <p class="lesson-text">{{ evalResult.lesson }}</p>
        </div>

        <!-- Next Actions -->
        <div class="next-actions">
          <button type="button" class="btn-retry" @click="retryScenario">Try Again</button>
          <button type="button" class="btn-next" @click="loadNextScenario">Next Scenario</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { getScenarios, getScenario, evaluateScenario } from '../services/api'

const scenariosList = ref([])
const channelFilter = ref('')
const selectedScenarioId = ref('bank-account-review')
const scenario = ref(null)
const selectedIds = ref([])
const evaluating = ref(false)
const evalResult = ref(null)

const scoreClass = computed(() => {
  if (!evalResult.value) return ''
  const s = evalResult.value.score
  if (s >= 80) return 'score-pass'
  if (s >= 50) return 'score-warn'
  return 'score-fail'
})

// fetch scenarios from backend
async function fetchScenarios() {
  try {
    const data = await getScenarios(null, channelFilter.value || null)
    scenariosList.value = data.items || []
    if (scenariosList.value.length > 0) {
      const match = scenariosList.value.find(s => s.id === selectedScenarioId.value)
      if (!match) {
        selectedScenarioId.value = scenariosList.value[0].id
      }
      await loadScenario(selectedScenarioId.value)
    }
  } catch (err) {
    console.error('Failed to load scenarios', err)
  }
}

async function setChannelFilter(ch) {
  channelFilter.value = ch
  await fetchScenarios()
}

async function loadScenario(id) {
  try {
    evalResult.value = null
    selectedIds.value = []
    scenario.value = await getScenario(id)
  } catch (err) {
    console.error('Failed to fetch scenario details', err)
  }
}

// toggle element selection flag
function toggleElement(id) {
  if (selectedIds.value.includes(id)) {
    selectedIds.value = selectedIds.value.filter(item => item !== id)
  } else {
    selectedIds.value.push(id)
  }
}

function getScenarioAddress(sc) {
  if (sc.channel === 'browser') return 'https://isolated-sandbox.local/browser'
  if (sc.channel === 'email') return 'inbox://mail.internal/message'
  if (sc.channel === 'sms') return 'sms://+91-messaging/gateway'
  return 'chat://secure-channel/session'
}

async function handleSubmit() {
  if (!scenario.value) return
  evaluating.value = true
  try {
    const res = await evaluateScenario(scenario.value.id, selectedIds.value)
    evalResult.value = res
  } catch (err) {
    alert(err.message || 'Evaluation failed')
  } finally {
    evaluating.value = false
  }
}

function retryScenario() {
  evalResult.value = null
  selectedIds.value = []
}

function loadNextScenario() {
  const currentIndex = scenariosList.value.findIndex(s => s.id === selectedScenarioId.value)
  if (currentIndex !== -1 && currentIndex + 1 < scenariosList.value.length) {
    selectedScenarioId.value = scenariosList.value[currentIndex + 1].id
  } else if (scenariosList.value.length > 0) {
    selectedScenarioId.value = scenariosList.value[0].id
  }
  loadScenario(selectedScenarioId.value)
}

onMounted(() => {
  fetchScenarios()
})
</script>

<style scoped>
.simulator-page {
  flex: 1;
  padding: 40px 24px;
  background-color: #09090b;
  background-image: radial-gradient(rgba(255, 255, 255, 0.08) 1px, transparent 1px);
  background-size: 24px 24px;
  min-height: 100vh;
}

.content-wrapper {
  max-width: 950px;
  margin: 0 auto;
}

.header-section {
  text-align: center;
  margin-bottom: 28px;
}

.header-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(236, 72, 153, 0.12);
  border: 1px solid rgba(236, 72, 153, 0.3);
  color: #ec4899;
  font-size: 11px;
  font-weight: 700;
  padding: 4px 12px;
  border-radius: 20px;
  margin-bottom: 12px;
  letter-spacing: 0.05em;
}

.badge-dot {
  width: 6px;
  height: 6px;
  background: #ec4899;
  border-radius: 50%;
}

.page-title {
  font-size: 2.2rem;
  font-weight: 800;
  color: #f8fafc;
  margin-bottom: 8px;
}

.highlight {
  color: #ec4899;
}

.page-desc {
  color: #94a3b8;
  font-size: 1.05rem;
  max-width: 640px;
  margin: 0 auto;
}

.glass-panel {
  background: rgba(18, 18, 24, 0.75);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
}

.selector-card {
  margin-bottom: 24px;
}

.selector-row {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
  align-items: flex-start;
  margin-bottom: 18px;
}

.selector-item {
  flex: 1;
  min-width: 260px;
}

.control-label {
  display: block;
  font-size: 12px;
  font-weight: 700;
  color: #cbd5e1;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 8px;
}

.scenario-select {
  width: 100%;
  background: rgba(9, 9, 11, 0.9);
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 10px;
  color: #f8fafc;
  padding: 10px 14px;
  font-size: 13.5px;
  font-weight: 600;
  cursor: pointer;
  outline: none;
}

.scenario-select:focus {
  border-color: #ec4899;
  box-shadow: 0 0 10px rgba(236, 72, 153, 0.3);
}

.filter-chips {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.filter-chip {
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  color: #94a3b8;
  padding: 6px 12px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: 0.2s;
}

.filter-chip:hover {
  background: rgba(255, 255, 255, 0.08);
  color: #fff;
}

.filter-chip.active {
  background: rgba(236, 72, 153, 0.18);
  border-color: #ec4899;
  color: #fff;
}

.scenario-info-banner {
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  padding-top: 16px;
}

.info-badges {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.diff-badge {
  font-size: 11px;
  font-weight: 800;
  padding: 3px 8px;
  border-radius: 6px;
}

.diff-easy {
  background: rgba(16, 185, 129, 0.2);
  color: #34d399;
  border: 1px solid rgba(16, 185, 129, 0.4);
}

.diff-medium {
  background: rgba(245, 158, 11, 0.2);
  color: #fbbf24;
  border: 1px solid rgba(245, 158, 11, 0.4);
}

.diff-hard {
  background: rgba(239, 68, 68, 0.2);
  color: #f87171;
  border: 1px solid rgba(239, 68, 68, 0.4);
}

.channel-badge, .xp-badge, .time-badge {
  font-size: 11px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: #cbd5e1;
}

.xp-badge {
  color: #ec4899;
  border-color: rgba(236, 72, 153, 0.3);
}

.scenario-context-box {
  background: rgba(255, 255, 255, 0.02);
  border-left: 3px solid #ec4899;
  padding: 10px 14px;
  border-radius: 0 8px 8px 0;
}

.context-label {
  font-size: 11px;
  font-weight: 700;
  color: #ec4899;
  margin-bottom: 2px;
}

.context-text {
  font-size: 13.5px;
  color: #f1f5f9;
  line-height: 1.4;
}

/* Virtual Window */
.virtual-window {
  padding: 0;
  overflow: hidden;
  margin-bottom: 24px;
}

.window-topbar {
  background: rgba(10, 10, 14, 0.95);
  padding: 12px 18px;
  display: flex;
  align-items: center;
  gap: 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.window-dots {
  display: flex;
  gap: 6px;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.dot-close { background: #ef4444; }
.dot-min { background: #f59e0b; }
.dot-expand { background: #10b981; }

.address-bar {
  flex: 1;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  padding: 6px 12px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: monospace;
  font-size: 12px;
  color: #cbd5e1;
}

.channel-icon {
  color: #ec4899;
  display: flex;
  align-items: center;
}

.status-pill {
  font-size: 11px;
  font-weight: 700;
  color: #94a3b8;
  background: rgba(255, 255, 255, 0.05);
  padding: 3px 8px;
  border-radius: 6px;
}

/* Interactive Canvas */
.interactive-canvas {
  padding: 24px;
}

.instruction-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
  color: #94a3b8;
  margin-bottom: 16px;
  padding-bottom: 10px;
  border-bottom: 1px dashed rgba(255, 255, 255, 0.1);
}

.selected-counter {
  font-weight: 800;
  color: #ec4899;
  background: rgba(236, 72, 153, 0.1);
  padding: 2px 10px;
  border-radius: 12px;
}

.elements-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 24px;
}

.interactive-elem {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  padding: 14px 18px;
  cursor: pointer;
  transition: all 0.2s ease;
  user-select: none;
}

.interactive-elem:hover {
  background: rgba(255, 255, 255, 0.06);
  border-color: rgba(255, 255, 255, 0.2);
  transform: translateX(2px);
}

.interactive-elem.flagged {
  background: rgba(239, 68, 68, 0.12);
  border: 1.5px solid #ef4444;
  box-shadow: 0 0 15px rgba(239, 68, 68, 0.25);
}

.elem-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.elem-type-label {
  font-size: 11.5px;
  font-weight: 700;
  color: #94a3b8;
  text-transform: uppercase;
}

.flag-indicator {
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.05em;
  padding: 2px 8px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.05);
  color: #64748b;
  transition: 0.2s;
}

.flagged .flag-indicator {
  background: #ef4444;
  color: white;
}

.elem-text {
  font-size: 14px;
  color: #f1f5f9;
  line-height: 1.5;
  word-break: break-word;
}

.canvas-actions {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 14px;
}

.clear-btn {
  background: none;
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: #94a3b8;
  padding: 10px 18px;
  border-radius: 10px;
  font-size: 13px;
  cursor: pointer;
  transition: 0.2s;
}

.clear-btn:hover:not(:disabled) {
  color: white;
  border-color: rgba(255, 255, 255, 0.3);
}

.clear-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

/* Shake hover animation */
@keyframes shake-hover {
  0% { transform: rotate(0deg); }
  25% { transform: rotate(-2deg); }
  50% { transform: rotate(2deg); }
  75% { transform: rotate(-1deg); }
  100% { transform: rotate(0deg); }
}

.submit-btn {
  background: #ec4899;
  color: white;
  border: none;
  border-radius: 12px;
  padding: 12px 26px;
  font-size: 14px;
  font-weight: 700;
  cursor: pointer;
  box-shadow: 0 0 20px rgba(236, 72, 153, 0.4);
  transition: all 0.2s ease;
}

.submit-btn:hover:not(:disabled) {
  animation: shake-hover 0.4s ease;
  box-shadow: 0 0 25px rgba(236, 72, 153, 0.6);
  transform: translateY(-1px);
}

.submit-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Results section */
.results-card {
  margin-top: 24px;
  border-width: 1.5px;
}

.score-pass {
  border-color: rgba(16, 185, 129, 0.5);
  background: rgba(16, 185, 129, 0.05);
}

.score-warn {
  border-color: rgba(245, 158, 11, 0.5);
  background: rgba(245, 158, 11, 0.05);
}

.score-fail {
  border-color: rgba(239, 68, 68, 0.5);
  background: rgba(239, 68, 68, 0.05);
}

.results-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.score-large {
  font-size: 3rem;
  font-weight: 800;
  color: #f8fafc;
  line-height: 1;
}

.score-sub {
  font-size: 13px;
  color: #94a3b8;
  margin-top: 4px;
}

.xp-badge-lg {
  font-size: 1.5rem;
  font-weight: 800;
  color: #ec4899;
}

.xp-max {
  font-size: 12px;
  color: #64748b;
}

.stats-row {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.stat-pill {
  flex: 1;
  min-width: 120px;
  padding: 12px;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.pill-correct {
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.3);
  color: #34d399;
}

.pill-missed {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: #f87171;
}

.pill-fp {
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.3);
  color: #fbbf24;
}

.stat-num {
  font-size: 1.5rem;
  font-weight: 800;
}

.stat-text {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}

.feedback-section {
  margin-bottom: 24px;
}

.feedback-title {
  font-size: 14px;
  font-weight: 700;
  color: #f8fafc;
  margin-bottom: 14px;
}

.indicator-feedback-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.feedback-item {
  padding: 12px 16px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(255, 255, 255, 0.06);
}

.item-hit {
  border-left: 3px solid #10b981;
}

.item-miss {
  border-left: 3px solid #ef4444;
}

.item-fp {
  border-left: 3px solid #f59e0b;
}

.fb-top {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 4px;
}

.fb-badge {
  font-size: 10px;
  font-weight: 800;
  padding: 2px 6px;
  border-radius: 4px;
}

.item-hit .fb-badge {
  background: rgba(16, 185, 129, 0.2);
  color: #34d399;
}

.item-miss .fb-badge {
  background: rgba(239, 68, 68, 0.2);
  color: #f87171;
}

.item-fp .fb-badge {
  background: rgba(245, 158, 11, 0.2);
  color: #fbbf24;
}

.fb-label {
  font-size: 13px;
  font-weight: 700;
  color: #f1f5f9;
}

.fb-text {
  font-size: 13px;
  color: #94a3b8;
  line-height: 1.4;
  margin: 0;
}

.lesson-box {
  background: rgba(236, 72, 153, 0.08);
  border: 1px solid rgba(236, 72, 153, 0.25);
  border-radius: 10px;
  padding: 14px;
  margin-bottom: 24px;
}

.lesson-header {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 800;
  color: #ec4899;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}

.lesson-text {
  font-size: 13.5px;
  color: #f8fafc;
  line-height: 1.4;
  margin: 0;
}

.next-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

.btn-retry {
  background: none;
  border: 1px solid rgba(255, 255, 255, 0.15);
  color: #cbd5e1;
  padding: 10px 18px;
  border-radius: 10px;
  font-size: 13px;
  cursor: pointer;
  transition: 0.2s;
}

.btn-retry:hover {
  background: rgba(255, 255, 255, 0.05);
  color: white;
}

.btn-next {
  background: #ec4899;
  color: white;
  border: none;
  padding: 10px 22px;
  border-radius: 10px;
  font-size: 13px;
  font-weight: 700;
  cursor: pointer;
  box-shadow: 0 0 15px rgba(236, 72, 153, 0.3);
  transition: 0.2s;
}

.btn-next:hover {
  box-shadow: 0 0 20px rgba(236, 72, 153, 0.5);
  transform: translateY(-1px);
}
</style>
