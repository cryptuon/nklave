<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

const route = useRoute()

const navItems = [
  { path: '/', name: 'Dashboard', icon: 'dashboard' },
  { path: '/validators', name: 'Validators', icon: 'key' },
  { path: '/decisions', name: 'Signing History', icon: 'history' },
  { path: '/signing-test', name: 'Signing Test', icon: 'edit' },
]

const isActive = (path: string) => {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}
</script>

<template>
  <aside class="w-64 bg-gray-800 border-r border-gray-700 flex flex-col">
    <!-- Logo -->
    <div class="h-16 flex items-center px-6 border-b border-gray-700">
      <div class="flex items-center space-x-3">
        <div class="w-8 h-8 bg-nklave-600 rounded-lg flex items-center justify-center">
          <svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
        </div>
        <span class="text-xl font-bold text-white">Nklave</span>
      </div>
    </div>

    <!-- Navigation -->
    <nav class="flex-1 py-4">
      <ul class="space-y-1 px-3">
        <li v-for="item in navItems" :key="item.path">
          <RouterLink
            :to="item.path"
            :class="[
              'flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
              isActive(item.path)
                ? 'bg-nklave-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-700'
            ]"
          >
            <!-- Icons -->
            <svg v-if="item.icon === 'dashboard'" class="w-5 h-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
            </svg>
            <svg v-else-if="item.icon === 'key'" class="w-5 h-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
            <svg v-else-if="item.icon === 'history'" class="w-5 h-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <svg v-else-if="item.icon === 'edit'" class="w-5 h-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
            </svg>
            {{ item.name }}
          </RouterLink>
        </li>
      </ul>
    </nav>

    <!-- Footer -->
    <div class="p-4 border-t border-gray-700">
      <div class="text-xs text-gray-500">
        <p>Nklave v0.1.0</p>
        <p class="mt-1">Secure Signing Layer</p>
      </div>
    </div>
  </aside>
</template>
