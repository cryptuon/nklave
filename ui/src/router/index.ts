import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('@/views/Dashboard.vue'),
    meta: { title: 'Dashboard' }
  },
  {
    path: '/validators',
    name: 'validators',
    component: () => import('@/views/Validators.vue'),
    meta: { title: 'Validators' }
  },
  {
    path: '/decisions',
    name: 'decisions',
    component: () => import('@/views/Decisions.vue'),
    meta: { title: 'Signing History' }
  },
  {
    path: '/signing-test',
    name: 'signing-test',
    component: () => import('@/views/SigningTest.vue'),
    meta: { title: 'Signing Test' }
  },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
})

// Update page title on navigation
router.beforeEach((to, _from, next) => {
  const title = to.meta.title as string | undefined
  document.title = title ? `${title} - Nklave` : 'Nklave'
  next()
})
