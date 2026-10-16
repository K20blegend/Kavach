import { createRouter, createWebHistory } from 'vue-router'
import ScannerView from '../views/ScannerView.vue'
import ResultsView from '../views/ResultsView.vue'
import SimulatorView from '../views/SimulatorView.vue'
import MessagesView from '../views/MessagesView.vue'

// router setup
const routes = [
  {
    path: '/',
    name: 'Scanner',
    component: ScannerView
  },
  {
    path: '/results',
    name: 'Results',
    component: ResultsView
  },
  {
    path: '/messages',
    name: 'Messages',
    component: MessagesView
  },
  {
    path: '/simulator',
    name: 'Simulator',
    component: SimulatorView
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
