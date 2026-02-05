<template>
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
    <div class="glass-strong w-full max-w-md rounded-2xl p-6 shadow-2xl">
      <!-- 步骤指示器 -->
      <div class="mb-6 flex items-center justify-center gap-2">
        <div
          v-for="s in 2"
          :key="s"
          class="h-2 w-8 rounded-full transition-colors"
          :class="step >= s ? 'bg-blue-500' : 'bg-gray-300 dark:bg-gray-600'"
        />
      </div>

      <!-- 步骤 1: 扫描 QR 码 -->
      <div v-if="step === 1">
        <div class="mb-4 text-center">
          <h3 class="text-xl font-bold text-gray-900 dark:text-white">设置两步验证</h3>
          <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">使用验证器应用扫描下方二维码</p>
        </div>

        <div v-if="loading" class="flex justify-center py-8">
          <div class="loading-spinner h-8 w-8" />
        </div>

        <div v-else-if="qrCode" class="space-y-4">
          <!-- QR 码 -->
          <div class="flex justify-center">
            <img
              :src="qrCode"
              alt="QR Code"
              class="h-48 w-48 rounded-lg border border-gray-200 bg-white p-2 dark:border-gray-700"
            />
          </div>

          <!-- 手动输入选项 -->
          <div class="text-center">
            <button
              class="text-sm text-blue-500 hover:text-blue-600 dark:text-blue-400"
              type="button"
              @click="showManualEntry = !showManualEntry"
            >
              <i class="fas fa-keyboard mr-1" />
              {{ showManualEntry ? '隐藏密钥' : '无法扫描？手动输入' }}
            </button>
          </div>

          <div
            v-if="showManualEntry"
            class="rounded-lg bg-gray-100 p-3 text-center dark:bg-gray-800"
          >
            <p class="mb-1 text-xs text-gray-500 dark:text-gray-400">手动输入此密钥：</p>
            <code class="select-all break-all font-mono text-sm text-gray-900 dark:text-white">
              {{ secret }}
            </code>
          </div>
        </div>

        <div v-else-if="error" class="py-8 text-center text-red-500">
          <i class="fas fa-exclamation-circle mr-2" />{{ error }}
        </div>

        <!-- 按钮 -->
        <div class="mt-6 flex gap-3">
          <button class="btn btn-secondary flex-1" type="button" @click="$emit('close')">
            取消
          </button>
          <button
            class="btn btn-primary flex-1"
            :disabled="!qrCode"
            type="button"
            @click="step = 2"
          >
            下一步
          </button>
        </div>
      </div>

      <!-- 步骤 2: 验证 -->
      <div v-else-if="step === 2">
        <div class="mb-4 text-center">
          <h3 class="text-xl font-bold text-gray-900 dark:text-white">验证设置</h3>
          <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
            输入验证器应用中显示的 6 位验证码
          </p>
        </div>

        <form class="space-y-4" @submit.prevent="handleVerify">
          <!-- 6位验证码输入 -->
          <div class="flex justify-center gap-2">
            <input
              v-for="(_, index) in 6"
              :key="index"
              :ref="(el) => (inputRefs[index] = el)"
              v-model="codeDigits[index]"
              class="h-12 w-10 rounded-lg border border-gray-300 bg-white text-center text-xl font-bold text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 dark:border-gray-600 dark:bg-gray-800 dark:text-white"
              inputmode="numeric"
              maxlength="1"
              pattern="[0-9]"
              type="text"
              @input="handleInput(index, $event)"
              @keydown="handleKeydown(index, $event)"
              @paste="handlePaste"
            />
          </div>

          <!-- 错误提示 -->
          <div
            v-if="verifyError"
            class="rounded-lg border border-red-500/30 bg-red-500/20 p-3 text-center text-xs text-red-800 dark:text-red-400"
          >
            <i class="fas fa-exclamation-triangle mr-2" />{{ verifyError }}
          </div>

          <!-- 按钮 -->
          <div class="flex gap-3">
            <button class="btn btn-secondary flex-1" type="button" @click="step = 1">返回</button>
            <button
              class="btn btn-primary flex-1"
              :disabled="verifying || code.length !== 6"
              type="submit"
            >
              <div v-if="verifying" class="loading-spinner mr-2" />
              {{ verifying ? '验证中...' : '完成设置' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, nextTick } from 'vue'
import { setup2FAApi, verifySetup2FAApi } from '@/utils/http_apis'

const emit = defineEmits(['close', 'success'])

const step = ref(1)
const loading = ref(false)
const error = ref('')
const qrCode = ref('')
const secret = ref('')
const setupToken = ref('')
const showManualEntry = ref(false)

const codeDigits = ref(['', '', '', '', '', ''])
const inputRefs = ref([])
const verifyError = ref('')
const verifying = ref(false)

const code = computed(() => codeDigits.value.join(''))

onMounted(() => {
  initSetup()
})

const initSetup = async () => {
  loading.value = true
  error.value = ''

  try {
    const result = await setup2FAApi()
    if (result.success) {
      qrCode.value = result.qrCode
      secret.value = result.secret
      setupToken.value = result.setupToken
    } else {
      error.value = result.message || '初始化失败'
    }
  } catch (err) {
    error.value = err.message || '初始化失败'
  } finally {
    loading.value = false
  }
}

const handleInput = (index, event) => {
  const value = event.target.value.replace(/\D/g, '')

  if (value.length === 1) {
    codeDigits.value[index] = value
    if (index < 5 && inputRefs.value[index + 1]) {
      inputRefs.value[index + 1].focus()
    }
  } else if (value.length === 0) {
    codeDigits.value[index] = ''
  }
}

const handleKeydown = (index, event) => {
  if (event.key === 'Backspace') {
    if (codeDigits.value[index] === '' && index > 0) {
      inputRefs.value[index - 1].focus()
    } else {
      codeDigits.value[index] = ''
    }
  } else if (event.key === 'ArrowLeft' && index > 0) {
    inputRefs.value[index - 1].focus()
  } else if (event.key === 'ArrowRight' && index < 5) {
    inputRefs.value[index + 1].focus()
  }
}

const handlePaste = (event) => {
  event.preventDefault()
  const pastedData = event.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)

  if (pastedData) {
    for (let i = 0; i < 6; i++) {
      codeDigits.value[i] = pastedData[i] || ''
    }
  }
}

const handleVerify = async () => {
  if (code.value.length !== 6 || verifying.value) return

  verifying.value = true
  verifyError.value = ''

  try {
    const result = await verifySetup2FAApi({
      setupToken: setupToken.value,
      code: code.value
    })

    if (result.success) {
      emit('success')
    } else {
      verifyError.value = result.message || '验证码错误'
      // 清空输入
      codeDigits.value = ['', '', '', '', '', '']
      nextTick(() => {
        if (inputRefs.value[0]) {
          inputRefs.value[0].focus()
        }
      })
    }
  } catch (err) {
    verifyError.value = err.message || '验证失败'
  } finally {
    verifying.value = false
  }
}
</script>
