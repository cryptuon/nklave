<script setup lang="ts">
import Sidebar from './Sidebar.vue'
import Header from './Header.vue'
</script>

<template>
  <div class="flex h-screen bg-gray-900">
    <!-- Sidebar -->
    <Sidebar />

    <!-- Main content area -->
    <div class="flex-1 flex flex-col overflow-hidden">
      <!-- Header -->
      <Header />

      <!-- Page content -->
      <main class="flex-1 overflow-y-auto p-6">
        <slot />
      </main>
    </div>
  </div>
</template>
