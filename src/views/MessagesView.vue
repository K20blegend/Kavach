<template>
  <div class="messages-page">
    <div class="content-wrapper">
      <div class="header-section">
        <h1 class="page-title">Scam Message <span class="highlight">Analyzer</span></h1>
        <p class="page-desc">Paste any suspicious email, SMS, or social DM to detect urgent threats, credential theft, and social engineering.</p>
      </div>

      <!-- Analysis Form Card -->
      <div class="analyzer-card glass-panel">
        <!-- Channel Selector -->
        <div class="channel-tabs">
          <button 
            type="button"
            class="tab-btn" 
            :class="{ active: channel === 'email' }"
            @click="channel = 'email'"
          >
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
              <rect width="20" height="16" x="2" y="4" rx="2"/>
              <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
            </svg>
            Email
          </button>
          <button 
            type="button"
            class="tab-btn" 
            :class="{ active: channel === 'sms' }"
            @click="channel = 'sms'"
          >
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
            SMS
          </button>
          <button 
            type="button"
            class="tab-btn" 
            :class="{ active: channel === 'social' }"
            @click="channel = 'social'"
          >
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="18" cy="5" r="3"/>
              <circle cx="6" cy="12" r="3"/>
              <circle cx="18" cy="19" r="3"/>
              <line x1="8.59" x2="15.42" y1="13.51" y2="17.49"/>
              <line x1="15.41" x2="8.59" y1="6.51" y2="10.49"/>
            </svg>
            Social Media
          </button>
        </div>

        <!-- Sample buttons -->
        <div class="samples-row">
          <span class="samples-label">Quick test samples:</span>
          <button type="button" class="sample-chip" @click="loadSample('lottery')">Jackpot Donation Scam</button>
          <button type="button" class="sample-chip" @click="loadSample('bank')">Bank Suspended Phish</button>
          <button type="button" class="sample-chip" @click="loadSample('crypto')">Crypto Seed Secret</button>
          <button type="button" class="sample-chip" @click="loadSample('clean')">Normal Meeting Message</button>
        </div>

        <!-- Message input -->
        <div class="form-group">
          <label class="input-label">Message Content</label>
          <textarea 
            v-model="messageText" 
            class="message-textarea" 
            rows="6" 
            placeholder="Paste suspicious message text here..."
            :disabled="loading"
          ></textarea>
        </div>

        <!-- Options row -->
        <div class="options-row">
          <label class="checkbox-label">
            <input type="checkbox" v-model="inspectLinks" :disabled="loading" />
            <span>Inspect links found inside message (checks target websites)</span>
          </label>

          <button 
            v-if="channel === 'email'" 
            type="button" 
            class="toggle-headers-btn" 
            @click="showHeaders = !showHeaders"
          >
            {{ showHeaders ? 'Hide Headers' : 'Add Raw Headers (Optional)' }}
          </button>
        </div>

        <!-- Optional headers -->
        <div v-if="channel === 'email' && showHeaders" class="form-group headers-group">
          <label class="input-label">Raw Email Headers (for SPF/DMARC and routing check)</label>
          <textarea 
            v-model="rawHeaders" 
            class="message-textarea headers-area" 
            rows="3" 
            placeholder="Paste full email headers (Received:, Authentication-Results:, etc.)..."
            :disabled="loading"
          ></textarea>
        </div>

        <!-- Action Button -->
        <div class="action-bar">
          <button 
            class="analyze-btn" 
            :disabled="loading || !messageText.trim()" 
            @click="handleAnalyze"
          >
            <span v-if="!loading">Analyze Message</span>
            <span v-else class="btn-loading">
              <span class="spinner"></span> Analyzing threats...
            </span>
          </button>
        </div>

        <div v-if="error" class="error-msg">
          {{ error }}
        </div>
      </div>

      <!-- Results View -->
      <div v-if="result" class="results-container">
        <!-- Score Card -->
        <div class="result-score-card glass-panel" :class="riskClass">
          <div class="score-info">
            <span class="score-badge">{{ verdictLabel }}</span>
            <div class="score-number-box">
              <span class="score-num">{{ result.risk_score }}</span>
              <span class="score-max">/ 100 Risk Score</span>
            </div>
            <p class="score-desc">
              {{ result.risk_score > 50 ? 'High probability of social engineering or phishing.' : result.risk_score > 25 ? 'Potential suspicious patterns detected; exercise caution.' : 'No prominent phishing or extortion indicators found.' }}
            </p>
          </div>
        </div>

        <!-- Threat Signals -->
        <div class="signals-section glass-panel">
          <h2 class="section-title">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Detected Threat Signals ({{ result.signals?.length || 0 }})
          </h2>

          <div v-if="!result.signals || result.signals.length === 0" class="empty-signals">
            No dangerous social engineering or credential triggers detected in this text.
          </div>

          <div v-else class="signals-list">
            <div 
              v-for="(signal, idx) in result.signals" 
              :key="idx" 
              class="signal-card"
              :class="'sev-' + signal.severity"
            >
              <div class="signal-top">
                <span class="signal-label">{{ signal.label }}</span>
                <span class="signal-tag">{{ signal.severity.toUpperCase() }}</span>
              </div>
              <p class="signal-expl">{{ signal.explanation }}</p>
              <div v-if="signal.matches && signal.matches.length" class="matched-chips">
                <span class="match-chip" v-for="(m, mIdx) in signal.matches" :key="mIdx">
                  "{{ m.text }}"
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- Detected Links -->
        <div v-if="result.links && result.links.length" class="links-section glass-panel">
          <h2 class="section-title">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
            Extracted Links ({{ result.links.length }})
          </h2>
          <div class="links-list">
            <div v-for="(link, lIdx) in result.links" :key="lIdx" class="link-item">
              <div class="link-url">{{ link.url }}</div>
              <div class="link-badges">
                <span v-if="link.shortener" class="warn-badge">Shortened URL</span>
                <span v-if="link.defanged" class="warn-badge">Defanged</span>
                <span v-if="link.scheme === 'http'" class="danger-badge">Unencrypted HTTP</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Recommendations -->
        <div class="recs-section glass-panel">
          <h2 class="section-title">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" x2="12" y1="8" y2="12"/>
              <line x1="12" x2="12.01" y1="16" y2="16"/>
            </svg>
            Security Recommendations
          </h2>
          <ul class="recs-list">
            <li v-for="(rec, rIdx) in result.recommendations" :key="rIdx">
              {{ rec }}
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { auditMessage } from '../services/api'

const channel = ref('email')
const messageText = ref('')
const rawHeaders = ref('')
const inspectLinks = ref(false)
const showHeaders = ref(false)
const loading = ref(false)
const error = ref('')
const result = ref(null)

const riskClass = computed(() => {
  if (!result.value) return ''
  const score = result.value.risk_score
  if (score >= 50) return 'risk-high'
  if (score >= 20) return 'risk-med'
  return 'risk-low'
})

const verdictLabel = computed(() => {
  if (!result.value) return ''
  const v = result.value.verdict
  if (v === 'high_risk') return 'HIGH RISK THREAT'
  if (v === 'caution') return 'CAUTION ADVISED'
  return 'LOW RISK'
})

// sample payloads for quick testing & demo
function loadSample(type) {
  if (type === 'lottery') {
    channel.value = 'email'
    messageText.value = 'I am Mrs. Mavis Wanczyk, the Mega Millions jackpot winner of $758 million. I have chosen to donate a total of $3,500,000 to five randomly selected individuals. Your email was selected through a random drawing.\n\nPlease find your donation code below:\n\nDONATION CODE: FE209387\n\nKindly reply with the donation code to proceed.\n\nRegards, \nMrs. Mavis L. Wanczyk'
    rawHeaders.value = 'From: "Mavis" <rudimar.bueno@gritsch.com.br>\nTo: Recipients <rudimar.bueno@gritsch.com.br>\nSubject: Congratulations\nReply-To: wanzcsk@gmail.com'
    showHeaders.value = true
    inspectLinks.value = false
  } else if (type === 'bank') {
    channel.value = 'sms'
    messageText.value = 'URGENT: Your Wells Fargo account has been locked due to suspicious activity. Enter your card PIN and verification OTP immediately at http://secure-wellsfargo-verify.top or your account will be suspended permanently.'
    inspectLinks.value = false
  } else if (type === 'crypto') {
    channel.value = 'social'
    messageText.value = 'Hello dear, our support bot detected an issue with your MetaMask wallet sync. Please reply with your 12-word seed phrase or private key so our technical engineer can restore your funds.'
    inspectLinks.value = false
  } else {
    channel.value = 'email'
    messageText.value = 'Hi Team, please find attached the agenda for our project sync tomorrow at 3 PM. Let me know if you would like to add any discussion points.'
    inspectLinks.value = false
  }
}

// fire audit request to fastAPI
async function handleAnalyze() {
  if (!messageText.value.trim()) return
  loading.value = true
  error.value = ''
  result.value = null

  try {
    const res = await auditMessage({
      text: messageText.value,
      channel: channel.value,
      raw_headers: showHeaders.value && rawHeaders.value.trim() ? rawHeaders.value.trim() : null,
      inspect_links: inspectLinks.value
    })
    result.value = res.result
  } catch (err) {
    error.value = err.message || 'Analysis failed. Please ensure the backend is running.'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.messages-page {
  flex: 1;
  padding: 40px 24px;
  background-color: #09090b;
  background-image: radial-gradient(rgba(255, 255, 255, 0.08) 1px, transparent 1px);
  background-size: 24px 24px;
  min-height: 100vh;
}

.content-wrapper {
  max-width: 900px;
  margin: 0 auto;
}

.header-section {
  text-align: center;
  margin-bottom: 32px;
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
  max-width: 600px;
  margin: 0 auto;
}

.glass-panel {
  background: rgba(18, 18, 24, 0.7);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
}

.channel-tabs {
  display: flex;
  gap: 10px;
  margin-bottom: 18px;
}

.tab-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 18px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 10px;
  color: #94a3b8;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: 0.2s ease;
}

.tab-btn:hover {
  color: #f8fafc;
  background: rgba(255, 255, 255, 0.08);
}

.tab-btn.active {
  color: #fff;
  background: rgba(236, 72, 153, 0.15);
  border-color: #ec4899;
}

.samples-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 18px;
}

.samples-label {
  font-size: 12px;
  color: #64748b;
  font-weight: 600;
}

.sample-chip {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: #cbd5e1;
  padding: 5px 12px;
  border-radius: 20px;
  font-size: 11px;
  cursor: pointer;
  transition: 0.2s;
}

.sample-chip:hover {
  background: rgba(236, 72, 153, 0.2);
  border-color: #ec4899;
  color: #fff;
}

.form-group {
  margin-bottom: 18px;
}

.input-label {
  display: block;
  font-size: 13px;
  font-weight: 600;
  color: #cbd5e1;
  margin-bottom: 8px;
}

.message-textarea {
  width: 100%;
  background: rgba(9, 9, 11, 0.8);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 12px;
  padding: 14px;
  color: #f8fafc;
  font-family: inherit;
  font-size: 14px;
  resize: vertical;
  transition: border-color 0.2s;
}

.message-textarea:focus {
  outline: none;
  border-color: #ec4899;
  box-shadow: 0 0 10px rgba(236, 72, 153, 0.3);
}

.options-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 20px;
}

.checkbox-label {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #94a3b8;
  cursor: pointer;
}

.checkbox-label input[type="checkbox"] {
  accent-color: #ec4899;
  width: 16px;
  height: 16px;
}

.toggle-headers-btn {
  background: none;
  border: none;
  color: #ec4899;
  font-size: 12px;
  cursor: pointer;
  text-decoration: underline;
}

.action-bar {
  display: flex;
  justify-content: flex-end;
}

/* Hover shake animation */
@keyframes shake-hover {
  0% { transform: rotate(0deg); }
  25% { transform: rotate(-2deg); }
  50% { transform: rotate(2deg); }
  75% { transform: rotate(-1deg); }
  100% { transform: rotate(0deg); }
}

.analyze-btn {
  background: #ec4899;
  color: white;
  border: none;
  border-radius: 12px;
  padding: 14px 28px;
  font-size: 14px;
  font-weight: 700;
  cursor: pointer;
  box-shadow: 0 0 20px rgba(236, 72, 153, 0.4);
  transition: all 0.2s ease;
}

.analyze-btn:hover:not(:disabled) {
  animation: shake-hover 0.4s ease;
  box-shadow: 0 0 25px rgba(236, 72, 153, 0.6);
  transform: translateY(-1px);
}

.analyze-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  box-shadow: none;
}

.btn-loading {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid white;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-msg {
  margin-top: 16px;
  padding: 12px 16px;
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.4);
  color: #fca5a5;
  border-radius: 10px;
  font-size: 13px;
}

/* Results section */
.results-container {
  margin-top: 32px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.result-score-card {
  padding: 24px;
  text-align: center;
}

.result-score-card.risk-high {
  border-color: rgba(239, 68, 68, 0.4);
  background: rgba(239, 68, 68, 0.08);
}

.result-score-card.risk-med {
  border-color: rgba(245, 158, 11, 0.4);
  background: rgba(245, 158, 11, 0.08);
}

.result-score-card.risk-low {
  border-color: rgba(16, 185, 129, 0.4);
  background: rgba(16, 185, 129, 0.08);
}

.score-badge {
  display: inline-block;
  padding: 4px 14px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.05em;
  margin-bottom: 12px;
}

.risk-high .score-badge {
  background: rgba(239, 68, 68, 0.2);
  color: #f87171;
  border: 1px solid rgba(239, 68, 68, 0.4);
}

.risk-med .score-badge {
  background: rgba(245, 158, 11, 0.2);
  color: #fbbf24;
  border: 1px solid rgba(245, 158, 11, 0.4);
}

.risk-low .score-badge {
  background: rgba(16, 185, 129, 0.2);
  color: #34d399;
  border: 1px solid rgba(16, 185, 129, 0.4);
}

.score-number-box {
  display: flex;
  align-items: baseline;
  justify-content: center;
  gap: 6px;
  margin-bottom: 6px;
}

.score-num {
  font-size: 3.2rem;
  font-weight: 800;
  color: #f8fafc;
}

.score-max {
  font-size: 1.1rem;
  color: #94a3b8;
}

.score-desc {
  font-size: 14px;
  color: #cbd5e1;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 1.15rem;
  font-weight: 700;
  color: #f8fafc;
  margin-bottom: 16px;
}

.empty-signals {
  color: #10b981;
  font-size: 14px;
  padding: 12px;
  background: rgba(16, 185, 129, 0.06);
  border-radius: 8px;
}

.signals-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.signal-card {
  padding: 14px 18px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
}

.signal-card.sev-high {
  border-left: 4px solid #ef4444;
}

.signal-card.sev-medium {
  border-left: 4px solid #f59e0b;
}

.signal-card.sev-low {
  border-left: 4px solid #3b82f6;
}

.signal-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}

.signal-label {
  font-weight: 700;
  color: #f1f5f9;
  font-size: 14px;
}

.signal-tag {
  font-size: 10px;
  font-weight: 800;
  padding: 2px 8px;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.1);
  color: #94a3b8;
}

.signal-expl {
  font-size: 13px;
  color: #94a3b8;
  margin-bottom: 8px;
}

.matched-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.match-chip {
  font-size: 11px;
  background: rgba(236, 72, 153, 0.15);
  color: #f472b6;
  border: 1px solid rgba(236, 72, 153, 0.3);
  padding: 2px 8px;
  border-radius: 4px;
  font-family: monospace;
}

.links-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.link-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 14px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 8px;
  word-break: break-all;
}

.link-url {
  font-size: 13px;
  color: #cbd5e1;
  font-family: monospace;
}

.warn-badge {
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(245, 158, 11, 0.2);
  color: #fbbf24;
}

.danger-badge {
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(239, 68, 68, 0.2);
  color: #f87171;
}

.recs-list {
  padding-left: 20px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  color: #cbd5e1;
  font-size: 13.5px;
  line-height: 1.5;
}
</style>
