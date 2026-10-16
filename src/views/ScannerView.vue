<template>
  <div class="home-box">
    <div class="two-columns">
      
      <!-- LEFT SIDE: big text and button -->
      <div class="left-col">
        <h1 class="main-title">
          Verify <span class="pink">links</span>, dissect
          <span class="pink">messages</span>, master
          your <span class="pink">digital safety</span>.
        </h1>

        <p class="desc">
          Instantly audit suspicious links, dissect fraudulent messages, and train
          your defense reflexes in one unified threat intelligence workspace.
        </p>

        <!-- CTA button - clicking this goes to results page now! -->
        <div class="btn-wrap">
          <button class="btn-primary" @click="goCheckUrl">
            Run Security Check
          </button>
        </div>
      </div>

      <!-- RIGHT SIDE: diagram with cards and search bar -->
      <div class="right-col">
        <div class="diagram-area">
          
          <!-- SVG lines connecting cards to center -->
          <svg class="pink-lines" viewBox="0 0 760 620">
            <!-- line to top left -->
            <path d="M340 240 C340 160, 270 120, 240 120" stroke="#ec4899" stroke-width="2" stroke-dasharray="4 4" fill="none" />
            <!-- line to top right -->
            <path d="M420 240 C420 160, 490 120, 520 120" stroke="#ec4899" stroke-width="2" stroke-dasharray="4 4" fill="none" />
            <!-- line down to trust badge -->
            <path d="M380 280 L380 340" stroke="#ec4899" stroke-width="2" stroke-dasharray="4 4" fill="none" />
            <!-- line to bottom left -->
            <path d="M330 380 C290 420, 250 460, 240 480" stroke="#ec4899" stroke-width="2" stroke-dasharray="4 4" fill="none" />
            <!-- line to bottom right -->
            <path d="M430 380 C470 420, 510 460, 520 480" stroke="#ec4899" stroke-width="2" stroke-dasharray="4 4" fill="none" />
          </svg>

          <!-- TOP ROW CARDS -->
          <div class="cards-row">
            <!-- Card 1: DNSBL -->
            <div class="white-card">
              <div class="card-head">
                <div class="pink-circle">
                  <!-- server database icon -->
                  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="white" stroke-width="2">
                    <ellipse cx="12" cy="5" rx="9" ry="3"/>
                    <path d="M3 5v6c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                    <path d="M3 11v6c0 1.66 4 3 9 3s9-1.34 9-3v-6"/>
                  </svg>
                  <span class="excl-mark">!</span>
                </div>
                <div class="card-title">DNS Blacklist (DNSBL)<br/>Lookups</div>
              </div>
              <div class="card-text">Checks if the domain or its IP is listed in known malicious DNS blacklists.</div>
              <div class="pink-pill">
                <span class="dot-warn">!</span> Listed in 2 blacklists
              </div>
            </div>

            <!-- Card 2: RDAP -->
            <div class="white-card">
              <div class="card-head">
                <div class="pink-circle">
                  <!-- calendar icon -->
                  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="white" stroke-width="2">
                    <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
                    <line x1="16" y1="2" x2="16" y2="6"/>
                    <line x1="8" y1="2" x2="8" y2="6"/>
                    <line x1="3" y1="10" x2="21" y2="10"/>
                  </svg>
                </div>
                <div class="card-title">RDAP Domain Registration<br/>Age Verification</div>
              </div>
              <div class="card-text">Checks domain creation date, registrant info and age.</div>
              <div class="pink-pill">
                <span class="dot-warn">!</span> Registered 12 days ago
              </div>
            </div>
          </div>

          <!-- CENTER: Search pill and trust indicator -->
          <div class="center-piece">
            <!-- search bar input -->
            <div class="search-pill">
              <div class="search-left">
                <!-- globe icon -->
                <svg viewBox="0 0 24 24" width="20" height="20" stroke="#000" stroke-width="2" fill="none">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="2" y1="12" x2="22" y2="12"/>
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
                <input
                  type="text"
                  v-model="myUrl"
                  placeholder="https://example.com"
                  @keyup.enter="goCheckUrl"
                />
              </div>

              <!-- pink magnifying glass button -->
              <div class="mag-wrapper" @click="goCheckUrl">
                <div class="burst-sparks">
                  <span></span><span></span><span></span>
                </div>
                <div class="mag-btn">
                  <svg viewBox="0 0 24 24" width="18" height="18" stroke="white" stroke-width="2.5" fill="none">
                    <circle cx="11" cy="11" r="7"/>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                  </svg>
                </div>
                <div class="mag-handle"></div>
              </div>
            </div>

            <!-- trust pill under the search bar -->
            <div class="trust-box">
              <div class="trust-badge">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="black" stroke-width="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <span class="trust-word">Trust</span>
                <span class="red-cross">✕</span>
              </div>
              <div class="lacking-pill">
                <span class="excl-white">!</span> Lacking Trust
              </div>
            </div>
          </div>

          <!-- BOTTOM ROW CARDS -->
          <div class="cards-row">
            <!-- Card 3: SSL -->
            <div class="white-card">
              <div class="card-head">
                <div class="pink-circle">
                  <!-- padlock icon -->
                  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="white" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                  </svg>
                </div>
                <div class="card-title">SSL/TLS Certificate<br/>Inspection</div>
              </div>
              <div class="card-text">Verifies certificate validity, issuer, and detects anomalies (e.g., self-signed, expired).</div>
              <div class="pink-pill">
                <span class="dot-warn">!</span> Invalid or missing certificate
              </div>
            </div>

            <!-- Card 4: Typosquatting -->
            <div class="white-card">
              <div class="card-head">
                <div class="pink-circle">
                  <span class="aa-letters">Aa</span>
                </div>
                <div class="card-title">Homograph / Typosquatting<br/>Distance Algorithms</div>
              </div>
              <div class="card-text">Detects visually similar domains and lookalike character substitutions (e.g., example.com vs. examp1e.com).</div>
              <div class="pink-pill">
                <span class="dot-warn">!</span> Potential lookalike detected
              </div>
            </div>
          </div>

        </div>
      </div>

    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

// the url entered by user
const myUrl = ref('https://example.com')

// function to navigate to the results page
function goCheckUrl() {
  let target = myUrl.value.trim()
  if (!target) {
    target = 'https://example.com'
  }
  // push to /results with query param so results page knows what was checked
  router.push({
    path: '/results',
    query: { url: target }
  })
}
</script>

<style scoped>
/* home page wrapper */
.home-box {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px 30px;
}

.two-columns {
  width: 100%;
  max-width: 1400px;
  display: grid;
  grid-template-columns: 1fr 1.3fr;
  gap: 40px;
  align-items: center;
}

/* left text */
.left-col {
  padding-right: 15px;
}

.main-title {
  font-family: 'Fraunces', serif;
  font-size: clamp(2.3rem, 4.2vw, 4rem);
  font-weight: 900;
  line-height: 1.15;
  color: white;
  margin-bottom: 20px;
}

.pink {
  color: #ec4899;
}

.desc {
  color: #cbd5e1;
  font-size: 1.05rem;
  line-height: 1.6;
  max-width: 520px;
  margin-bottom: 35px;
}

.btn-wrap {
  margin-top: 10px;
}

/* right column diagram */
.right-col {
  display: flex;
  justify-content: center;
}

.diagram-area {
  position: relative;
  width: 100%;
  max-width: 740px;
  min-height: 580px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.pink-lines {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 1;
}

/* rows of cards */
.cards-row {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  z-index: 2;
}

/* white cards matching the image */
.white-card {
  background: white;
  border: 1.8px solid #ec4899;
  border-radius: 18px;
  padding: 16px 18px;
  width: 48%;
  max-width: 320px;
  box-shadow: 0 8px 25px rgba(0,0,0,0.4);
}

.card-head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}

.pink-circle {
  width: 42px;
  height: 42px;
  background: #ec4899;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  flex-shrink: 0;
}

.excl-mark {
  position: absolute;
  bottom: -2px;
  right: -2px;
  background: red;
  color: white;
  font-size: 10px;
  font-weight: bold;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid white;
}

.aa-letters {
  color: white;
  font-weight: 800;
  font-size: 18px;
}

.card-title {
  color: #0f172a;
  font-weight: 800;
  font-size: 13.5px;
  line-height: 1.25;
}

.card-text {
  color: #475569;
  font-size: 11.5px;
  line-height: 1.45;
  margin-bottom: 12px;
}

.pink-pill {
  background: #ffe4e6;
  color: #e11d48;
  font-size: 11px;
  font-weight: 700;
  padding: 4px 10px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.dot-warn {
  width: 13px;
  height: 13px;
  background: #ec4899;
  color: white;
  border-radius: 50%;
  font-size: 9px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 900;
}

/* center hub */
.center-piece {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  z-index: 3;
  margin: 15px 0;
}

.search-pill {
  background: white;
  border-radius: 999px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 5px 8px 5px 18px;
  width: 100%;
  max-width: 430px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.5);
  border: 2px solid #e2e8f0;
}

.search-left {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
}

.search-left input {
  border: none;
  outline: none;
  width: 100%;
  font-size: 14.5px;
  font-weight: 700;
  color: #0f172a;
  background: transparent;
}

/* magnifying glass */
.mag-wrapper {
  position: relative;
  cursor: pointer;
}

.mag-btn {
  width: 40px;
  height: 40px;
  background: #ec4899;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  z-index: 2;
}

.mag-btn:hover {
  transform: scale(1.06);
}

.burst-sparks {
  position: absolute;
  top: -10px;
  right: 5px;
  display: flex;
  gap: 3px;
}

.burst-sparks span {
  width: 2px;
  height: 6px;
  background: #ec4899;
  border-radius: 2px;
}

.burst-sparks span:nth-child(1) { transform: rotate(-30deg); }
.burst-sparks span:nth-child(2) { height: 8px; margin-top: -2px; }
.burst-sparks span:nth-child(3) { transform: rotate(30deg); }

.mag-handle {
  position: absolute;
  bottom: -28px;
  right: -20px;
  width: 14px;
  height: 42px;
  background: #0f172a;
  border-radius: 6px;
  transform: rotate(-45deg);
  z-index: 1;
}

.mag-handle::after {
  content: '';
  position: absolute;
  bottom: 0;
  width: 100%;
  height: 10px;
  background: #ec4899;
  border-radius: 0 0 6px 6px;
}

/* trust badge under search */
.trust-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
}

.trust-badge {
  background: white;
  border-radius: 999px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 14px;
  border: 1px solid #e2e8f0;
  box-shadow: 0 5px 15px rgba(0,0,0,0.3);
}

.trust-word {
  color: black;
  font-weight: 800;
  font-size: 15px;
}

.red-cross {
  color: #ec4899;
  font-weight: 900;
  background: #ffe4e6;
  border-radius: 50%;
  width: 18px;
  height: 18px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
}

.lacking-pill {
  background: #ec4899;
  color: white;
  font-weight: 800;
  font-size: 12px;
  padding: 4px 14px;
  border-radius: 999px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.excl-white {
  background: white;
  color: #ec4899;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  font-size: 10px;
  font-weight: 900;
  display: flex;
  align-items: center;
  justify-content: center;
}

/* responsive */
@media (max-width: 1100px) {
  .two-columns {
    grid-template-columns: 1fr;
  }
  .left-col {
    text-align: center;
  }
  .desc {
    margin-left: auto;
    margin-right: auto;
  }
}

@media (max-width: 768px) {
  .cards-row {
    flex-direction: column;
  }
  .white-card {
    width: 100%;
    max-width: 100%;
  }
  .pink-lines {
    display: none;
  }
  .mag-handle {
    display: none;
  }
}
</style>
