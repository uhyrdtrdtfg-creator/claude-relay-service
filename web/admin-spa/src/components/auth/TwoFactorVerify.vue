<template>
  <div class="space-y-4 sm:space-y-6">
    <div class="text-center">
      <div
        class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-blue-500/20"
      >
        <i class="fas fa-shield-alt text-2xl text-blue-500" />
      </div>
      <h2 class="mb-2 text-xl font-bold text-gray-900 dark:text-white sm:text-2xl">两步验证</h2>
      <p class="text-sm text-gray-600 dark:text-gray-400">请输入验证器应用中显示的 6 位验证码</p>
    </div>

    <form class="space-y-4" @submit.prevent="handleVerify">
      <!-- 6位验证码输入 -->
      <div class="flex justify-center gap-2 sm:gap-3">
        <input
          v-for="(_, index) in 6"
          :key="index"
          :ref="(el) => (inputRefs[index] = el)"
          v-model="codeDigits[index]"
          class="h-12 w-10 rounded-lg border border-gray-300 bg-white text-center text-xl font-bold text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 dark:border-gray-600 dark:bg-gray-800 dark:text-white sm:h-14 sm:w-12 sm:text-2xl"
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
        v-if="error"
        class="rounded-lg border border-red-500/30 bg-red-500/20 p-3 text-center text-xs text-red-800 dark:text-red-400 sm:text-sm"
      >
        <i class="fas fa-exclamation-triangle mr-2" />{{ error }}
        <span v-if="remainingAttempts !== null" class="ml-1">
          (剩余 {{ remainingAttempts }} 次尝试)
        </span>
      </div>

      <!-- 验证按钮 -->
      <button
        class="btn btn-primary w-full px-4 py-3 text-base font-semibold sm:px-6 sm:py-4 sm:text-lg"
        :disabled="loading || code.length !== 6"
        type="submit"
      >
        <div v-if="loading" class="loading-spinner mr-2" />
        <i v-else class="fas fa-check mr-2" />
        {{ loading ? '验证中...' : '验证' }}
      </button>

      <!-- 返回登录 -->
      <button
        class="w-full text-center text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
        type="button"
        @click="$emit('cancel')"
      >
        <i class="fas fa-arrow-left mr-2" />返回登录
      </button>
    </form>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, nextTick } from 'vue'

const emit = defineEmits(['verify', 'cancel'])

const props = defineProps({
  loading: {
    type: Boolean,
    default: false
  },
  error: {
    type: String,
    default: ''
  },
  remainingAttempts: {
    type: Number,
    default: null
  }
})

const codeDigits = ref(['', '', '', '', '', ''])
const inputRefs = ref([])

const code = computed(() => codeDigits.value.join(''))

onMounted(() => {
  // 自动聚焦第一个输入框
  nextTick(() => {
    if (inputRefs.value[0]) {
      inputRefs.value[0].focus()
    }
  })
})

const handleInput = (index, event) => {
  const value = event.target.value.replace(/\D/g, '')

  if (value.length === 1) {
    codeDigits.value[index] = value
    // 自动跳到下一个输入框
    if (index < 5 && inputRefs.value[index + 1]) {
      inputRefs.value[index + 1].focus()
    }
  } else if (value.length === 0) {
    codeDigits.value[index] = ''
  }

  // 如果输入完成，自动提交
  if (code.value.length === 6) {
    handleVerify()
  }
}

const handleKeydown = (index, event) => {
  // 处理退格键
  if (event.key === 'Backspace') {
    if (codeDigits.value[index] === '' && index > 0) {
      // 如果当前框为空，跳到前一个
      inputRefs.value[index - 1].focus()
    } else {
      codeDigits.value[index] = ''
    }
  }
  // 处理左箭头
  else if (event.key === 'ArrowLeft' && index > 0) {
    inputRefs.value[index - 1].focus()
  }
  // 处理右箭头
  else if (event.key === 'ArrowRight' && index < 5) {
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
    // 聚焦最后一个填入的输入框
    const lastIndex = Math.min(pastedData.length, 6) - 1
    if (lastIndex >= 0 && inputRefs.value[lastIndex]) {
      inputRefs.value[lastIndex].focus()
    }
    // 如果粘贴了完整的 6 位码，自动提交
    if (pastedData.length === 6) {
      nextTick(() => handleVerify())
    }
  }
}

const handleVerify = () => {
  if (code.value.length === 6 && !props.loading) {
    emit('verify', code.value)
  }
}

// 清空输入（供父组件调用）
const clear = () => {
  codeDigits.value = ['', '', '', '', '', '']
  nextTick(() => {
    if (inputRefs.value[0]) {
      inputRefs.value[0].focus()
    }
  })
}

defineExpose({ clear })
</script>
