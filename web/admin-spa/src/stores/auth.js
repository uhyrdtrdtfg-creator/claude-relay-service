import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import router from '@/router'

import { loginApi, getAuthUserApi, getOemSettingsApi, verify2FAApi } from '@/utils/http_apis'

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const isLoggedIn = ref(false)
  const authToken = ref(localStorage.getItem('authToken') || '')
  const username = ref('')
  const loginError = ref('')
  const loginLoading = ref(false)
  const oemSettings = ref({
    siteName: 'Claude Relay Service',
    siteIcon: '',
    siteIconData: '',
    faviconData: ''
  })
  const oemLoading = ref(true)

  // 2FA 相关状态
  const requiresTwoFactor = ref(false)
  const partialToken = ref('')
  const twoFactorLoading = ref(false)

  // 计算属性
  const isAuthenticated = computed(() => !!authToken.value && isLoggedIn.value)
  const token = computed(() => authToken.value)
  const user = computed(() => ({ username: username.value }))

  // 方法
  async function login(credentials) {
    loginLoading.value = true
    loginError.value = ''
    requiresTwoFactor.value = false
    partialToken.value = ''

    try {
      const result = await loginApi(credentials)

      if (result.success) {
        // 检查是否需要 2FA
        if (result.requiresTwoFactor) {
          requiresTwoFactor.value = true
          partialToken.value = result.partialToken
          // 不跳转，等待 2FA 验证
        } else {
          // 普通登录成功
          authToken.value = result.token
          username.value = result.username || credentials.username
          isLoggedIn.value = true
          localStorage.setItem('authToken', result.token)

          await router.push('/dashboard')
        }
      } else {
        loginError.value = result.message || '登录失败'
      }
    } catch (error) {
      loginError.value = error.message || '登录失败，请检查用户名和密码'
    } finally {
      loginLoading.value = false
    }
  }

  // 验证 2FA
  async function verify2FA(code) {
    twoFactorLoading.value = true

    try {
      const result = await verify2FAApi({
        partialToken: partialToken.value,
        code
      })

      if (result.success) {
        // 2FA 验证成功
        authToken.value = result.token
        username.value = result.username
        isLoggedIn.value = true
        localStorage.setItem('authToken', result.token)

        // 重置 2FA 状态
        requiresTwoFactor.value = false
        partialToken.value = ''

        await router.push('/dashboard')
        return { success: true }
      } else {
        return {
          success: false,
          message: result.message || '验证码错误',
          remainingAttempts: result.remainingAttempts
        }
      }
    } catch (error) {
      return {
        success: false,
        message: error.message || '验证失败，请重试'
      }
    } finally {
      twoFactorLoading.value = false
    }
  }

  // 取消 2FA 验证，返回登录页
  function cancel2FA() {
    requiresTwoFactor.value = false
    partialToken.value = ''
    loginError.value = ''
  }

  function logout() {
    isLoggedIn.value = false
    authToken.value = ''
    username.value = ''
    localStorage.removeItem('authToken')
    router.push('/login')
  }

  function checkAuth() {
    if (authToken.value) {
      isLoggedIn.value = true
      // 验证token有效性
      verifyToken()
    }
  }

  async function verifyToken() {
    try {
      const userResult = await getAuthUserApi()
      if (!userResult.success || !userResult.user) {
        logout()
        return
      }
      username.value = userResult.user.username
    } catch (error) {
      logout()
    }
  }

  async function loadOemSettings() {
    oemLoading.value = true
    try {
      const result = await getOemSettingsApi()
      if (result.success && result.data) {
        oemSettings.value = { ...oemSettings.value, ...result.data }

        if (result.data.siteIconData || result.data.siteIcon) {
          const link = document.querySelector("link[rel*='icon']") || document.createElement('link')
          link.type = 'image/x-icon'
          link.rel = 'shortcut icon'
          link.href = result.data.siteIconData || result.data.siteIcon
          document.getElementsByTagName('head')[0].appendChild(link)
        }

        if (result.data.siteName) {
          document.title = `${result.data.siteName} - 管理后台`
        }
      }
    } catch (error) {
      console.error('加载OEM设置失败:', error)
    } finally {
      oemLoading.value = false
    }
  }

  return {
    // 状态
    isLoggedIn,
    authToken,
    username,
    loginError,
    loginLoading,
    oemSettings,
    oemLoading,

    // 2FA 状态
    requiresTwoFactor,
    partialToken,
    twoFactorLoading,

    // 计算属性
    isAuthenticated,
    token,
    user,

    // 方法
    login,
    logout,
    checkAuth,
    loadOemSettings,
    verify2FA,
    cancel2FA
  }
})
