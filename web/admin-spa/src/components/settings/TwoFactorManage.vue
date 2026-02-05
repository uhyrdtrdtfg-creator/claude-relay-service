<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
          <i class="fas fa-shield-alt mr-2 text-blue-500" />
          两步验证 (2FA)
        </h3>
        <p class="mt-1 text-sm text-gray-600 dark:text-gray-400">使用验证器应用增强账户安全性</p>
      </div>

      <div v-if="loading" class="loading-spinner h-6 w-6" />
      <div v-else>
        <span
          v-if="enabled"
          class="inline-flex items-center rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400"
        >
          <i class="fas fa-check-circle mr-1" />已启用
        </span>
        <span
          v-else
          class="inline-flex items-center rounded-full bg-gray-100 px-3 py-1 text-sm font-medium text-gray-600 dark:bg-gray-700 dark:text-gray-400"
        >
          <i class="fas fa-times-circle mr-1" />未启用
        </span>
      </div>
    </div>

    <!-- 启用时间 -->
    <div v-if="enabled && enabledAt" class="text-sm text-gray-500 dark:text-gray-400">
      <i class="fas fa-clock mr-1" />
      启用于：{{ formatDate(enabledAt) }}
    </div>

    <!-- 操作按钮 -->
    <div class="flex gap-3">
      <button v-if="!enabled" class="btn btn-primary" :disabled="loading" @click="showSetup = true">
        <i class="fas fa-shield-alt mr-2" />
        启用两步验证
      </button>

      <button v-else class="btn btn-danger" :disabled="loading" @click="showDisableConfirm = true">
        <i class="fas fa-shield-alt mr-2" />
        禁用两步验证
      </button>
    </div>

    <!-- 设置弹窗 -->
    <TwoFactorSetup v-if="showSetup" @close="showSetup = false" @success="handleSetupSuccess" />

    <!-- 禁用确认弹窗 -->
    <div
      v-if="showDisableConfirm"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
    >
      <div class="glass-strong w-full max-w-md rounded-2xl p-6 shadow-2xl">
        <div class="mb-4 text-center">
          <div
            class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-red-500/20"
          >
            <i class="fas fa-exclamation-triangle text-2xl text-red-500" />
          </div>
          <h3 class="text-xl font-bold text-gray-900 dark:text-white">禁用两步验证</h3>
          <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
            禁用后，登录时将不再需要验证码。请输入当前密码确认操作。
          </p>
        </div>

        <form class="space-y-4" @submit.prevent="handleDisable">
          <div>
            <label class="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
              当前密码
            </label>
            <input
              v-model="disablePassword"
              class="form-input w-full"
              placeholder="请输入当前密码"
              required
              type="password"
            />
          </div>

          <div
            v-if="disableError"
            class="rounded-lg border border-red-500/30 bg-red-500/20 p-3 text-center text-xs text-red-800 dark:text-red-400"
          >
            <i class="fas fa-exclamation-triangle mr-2" />{{ disableError }}
          </div>

          <div class="flex gap-3">
            <button class="btn btn-secondary flex-1" type="button" @click="closeDisableConfirm">
              取消
            </button>
            <button
              class="btn btn-danger flex-1"
              :disabled="disabling || !disablePassword"
              type="submit"
            >
              <div v-if="disabling" class="loading-spinner mr-2" />
              {{ disabling ? '处理中...' : '确认禁用' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { get2FAStatusApi, disable2FAApi } from '@/utils/http_apis'
import TwoFactorSetup from './TwoFactorSetup.vue'

const loading = ref(false)
const enabled = ref(false)
const enabledAt = ref(null)
const showSetup = ref(false)
const showDisableConfirm = ref(false)
const disablePassword = ref('')
const disableError = ref('')
const disabling = ref(false)

onMounted(() => {
  loadStatus()
})

const loadStatus = async () => {
  loading.value = true
  try {
    const result = await get2FAStatusApi()
    if (result.success) {
      enabled.value = result.twoFactorEnabled
      enabledAt.value = result.twoFactorEnabledAt
    }
  } catch (err) {
    console.error('Failed to load 2FA status:', err)
  } finally {
    loading.value = false
  }
}

const handleSetupSuccess = () => {
  showSetup.value = false
  loadStatus()
}

const closeDisableConfirm = () => {
  showDisableConfirm.value = false
  disablePassword.value = ''
  disableError.value = ''
}

const handleDisable = async () => {
  if (!disablePassword.value || disabling.value) return

  disabling.value = true
  disableError.value = ''

  try {
    const result = await disable2FAApi({ password: disablePassword.value })
    if (result.success) {
      closeDisableConfirm()
      loadStatus()
    } else {
      disableError.value = result.message || '操作失败'
    }
  } catch (err) {
    disableError.value = err.message || '操作失败'
  } finally {
    disabling.value = false
  }
}

const formatDate = (dateStr) => {
  if (!dateStr) return ''
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  })
}
</script>
