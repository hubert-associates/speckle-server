<!-- eslint-disable vuejs-accessibility/click-events-have-key-events -->
<template>
  <div>
    <div :class="`${background ? 'px-2 bg-foundation rounded-md shadow-xl' : ''}`">
      <div
        v-if="!allCompleted"
        :class="`grid gap-2 ${showIntro ? 'px-4 grid-cols-5' : 'grid-cols-4'}`"
      >
        <div
          v-if="showIntro"
          class="flex-col justify-around px-2 h-full py-2 md:col-span-1 hidden lg:flex"
        >
          <div>Quickstart Checklist</div>
          <div class="text-sm text-foreground-2">
            Become a Speckle pro in four steps!
          </div>
          <div class="space-x-1">
            <FormButton v-if="!allCompleted" size="sm" @click="dismissChecklist()">
              I'll do it later
            </FormButton>
            <FormButton
              v-if="!allCompleted"
              text
              size="xs"
              @click="dismissChecklistForever()"
            >
              Don't show again
            </FormButton>
          </div>
        </div>
        <div class="grid grid-cols-4 grow col-span-5 lg:col-span-4">
          <div
            v-for="(step, idx) in steps"
            :key="idx"
            class="py-2 col-span-4 sm:col-span-2 lg:col-span-1"
          >
            <div
              :class="`
          ${
            step.active
              ? 'bg-primary text-foreground-on-primary shadow hover:shadow-md scale-100'
              : 'text-foreground-2 hover:bg-primary-muted scale-95'
          } 
          transition rounded-md flex flex-col justify-between px-2 cursor-pointer h-full`"
              @click.stop="
                !step.active
                  ? activateStep(idx)
                  : idx === 0 || steps[idx - 1].completed
                  ? step.action()
                  : goToFirstUncompletedStep()
              "
            >
              <div
                :class="`text-xl font-bold flex items-center justify-between ${
                  step.active ? 'text-foreground-on-primary' : 'text-foreground-2'
                }`"
              >
                <span>{{ idx + 1 }}</span>
                <Component
                  :is="step.icon"
                  v-if="!step.completed"
                  :class="`w-4 h-4 mt-1`"
                />
                <CheckCircleIcon v-else class="w-4 h-4 mt-1 text-primary" />
              </div>
              <div
                :class="`${step.active ? 'font-bold text-forergound-on-primary' : ''}`"
              >
                {{ step.title }}
              </div>
              <div class="text-xs mt-[2px]">{{ step.blurb }}</div>
              <div class="h-10 flex items-center justify-between">
                <div
                  v-if="idx === 0 || steps[idx - 1].completed"
                  class="flex justify-between items-center py-2 w-full"
                >
                  <FormButton
                    v-if="!step.completed && step.active"
                    size="sm"
                    :disabled="!step.active"
                    color="invert"
                    @click.stop="step.action"
                  >
                    {{ step.cta }}
                  </FormButton>

                  <FormButton
                    v-if="step.active && !step.completed"
                    v-tippy="'Mark completed'"
                    text
                    link
                    size="xs"
                    color="invert"
                    @click.stop="markComplete(idx)"
                  >
                    <!-- Mark as complete -->
                    <OutlineCheckCircleIcon class="w-4 h-4" />
                  </FormButton>
                  <span v-if="step.completed" class="text-xs font-bold">
                    Completed!
                  </span>
                  <FormButton
                    v-if="step.completed && step.active"
                    text
                    link
                    size="xs"
                    color="invert"
                    @click.stop="step.action"
                  >
                    {{ step.postCompletionCta }}
                  </FormButton>
                </div>
                <div v-else-if="step.active" class="text-sm">
                  <FormButton
                    link
                    size="xs"
                    color="invert"
                    @click.stop="goToFirstUncompletedStep()"
                  >
                    Complete the previous step!
                  </FormButton>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div
          v-if="showIntro"
          class="lg:hidden col-span-5 pb-3 pt-2 text-center space-x-2"
        >
          <FormButton v-if="!allCompleted" size="sm" @click="dismissChecklist()">
            I'll do it later
          </FormButton>
          <FormButton
            v-if="!allCompleted"
            text
            size="xs"
            @click="dismissChecklistForever()"
          >
            Don't show again
          </FormButton>
        </div>
      </div>
      <div
        v-else
        class="flex flex-col sm:flex-row items-center justify-center flex-1 space-x-2 py-4"
      >
        <div class="w-6 h-6">
          <!-- <CheckCircleIcon class="absolute w-6 h-6 text-primary" /> -->
          <CheckCircleIcon class="w-6 h-6 text-primary animate-ping animate-pulse" />
        </div>
        <div class="text-sm max-w-lg grow">
          <b>All done!</b>
          PS: the
          <FormButton to="https://speckle.community" target="_blank" size="sm" link>
            Community Forum
          </FormButton>
          is there to help!
        </div>
        <div>
          <FormButton text size="sm" @click="closeChecklist()">Close</FormButton>
        </div>
      </div>
    </div>

    <!--
      This is used as a dismissal prompt from when showing the checklist on top of the
      viewer. It does not directly dismiss the checklist as we still want to show it
      on the main dasboard page.  
    -->
    <div v-if="showBottomEscape" class="text-center mt-2">
      <FormButton size="sm" @click="$emit('dismiss')">
        I'll do it later - let me explore first!
      </FormButton>
    </div>

    <OnboardingDialogManager
      v-model:open="showManagerDownloadDialog"
      @done="markComplete(0)"
      @cancel="showManagerDownloadDialog = false"
    ></OnboardingDialogManager>
    <OnboardingDialogAccountLink
      v-model:open="showAccountLinkDialog"
      @done="markComplete(1)"
      @cancel="showAccountLinkDialog = false"
    >
      <template #header>Desktop Login</template>
    </OnboardingDialogAccountLink>
    <OnboardingDialogFirstSend
      v-model:open="showFirstSendDialog"
      @done="markComplete(2)"
      @cancel="showFirstSendDialog = false"
    >
      <template #header>Your First Upload</template>
    </OnboardingDialogFirstSend>
    <ServerInviteDialog
      v-model:open="showServerInviteDialog"
      @update:open="(v) => (!v ? markComplete(3) : '')"
    />
  </div>
</template>
<script setup lang="ts">
import {
  CheckCircleIcon,
  ShareIcon,
  ComputerDesktopIcon,
  UserPlusIcon,
  CloudArrowUpIcon
} from '@heroicons/vue/24/solid'
import { CheckCircleIcon as OutlineCheckCircleIcon } from '@heroicons/vue/24/outline'
import { useSynchronizedCookie } from '~~/lib/common/composables/reactiveCookie'
import { useMixpanel } from '~~/lib/core/composables/mp'

withDefaults(
  defineProps<{ showIntro: boolean; showBottomEscape: boolean; background: boolean }>(),
  {
    showIntro: false,
    showBottomEscape: false,
    background: false
  }
)

const mp = useMixpanel()

const emit = defineEmits(['dismiss'])

const showManagerDownloadDialog = ref(false)
const showAccountLinkDialog = ref(false)
const showFirstSendDialog = ref(false)
const showServerInviteDialog = ref(false)

const hasDownloadedManager = useSynchronizedCookie<boolean>(`hasDownloadedManager`, {
  default: () => false
})
const hasLinkedAccount = useSynchronizedCookie<boolean>(`hasLinkedAccount`, {
  default: () => false
})
const hasViewedFirstSend = useSynchronizedCookie<boolean>(`hasViewedFirstSend`, {
  default: () => false
})
const hasSharedProject = useSynchronizedCookie<boolean>(`hasSharedProject`, {
  default: () => false
})
const hasCompletedChecklistV1 = useSynchronizedCookie<boolean>(
  `hasCompletedChecklistV1`,
  { default: () => false }
)
const hasDismissedChecklistTime = useSynchronizedCookie<string | undefined>(
  `hasDismissedChecklistTime`,
  { default: () => undefined }
)

const hasDismissedChecklistForever = useSynchronizedCookie<boolean | undefined>(
  `hasDismissedChecklistForever`,
  { default: () => false }
)

const getStatus = () => {
  return {
    hasDownloadedManager: hasDownloadedManager.value,
    hasLinkedAccount: hasLinkedAccount.value,
    hasViewedFirstSend: hasViewedFirstSend.value,
    hasSharedProject: hasSharedProject.value
  }
}

const steps = ref([
  {
    title: 'Install Manager ⚙️',
    blurb: 'Use Manager to install the Speckle Connectors for your apps!',
    active: false,
    cta: "Let's go!",
    postCompletionCta: 'Download Again',
    action: () => {
      showManagerDownloadDialog.value = true
    },
    completionAction: () => {
      showManagerDownloadDialog.value = false
      hasDownloadedManager.value = true
      mp.track('Onboarding Action', {
        type: 'action',
        name: 'checklist',
        action: 'step-completed',
        stepName: 'download manager'
      })
    },
    completed: hasDownloadedManager.value,
    icon: ComputerDesktopIcon
  },
  {
    title: 'Log In 🔑',
    blurb: 'Authorise our application connectors to send data to Speckle.',
    active: false,
    cta: "Let's go!",
    postCompletionCta: 'Login Again',
    action: () => {
      showAccountLinkDialog.value = true
    },
    completionAction: () => {
      showAccountLinkDialog.value = false
      hasLinkedAccount.value = true
      mp.track('Onboarding Action', {
        type: 'action',
        name: 'checklist',
        action: 'step-completed',
        stepName: 'manager login'
      })
    },
    completed: hasLinkedAccount.value,
    icon: UserPlusIcon
  },
  {
    title: 'Your First Model Upload ⬆️',
    blurb: 'Use your favourite design app to send your first model to Speckle.',
    active: false,
    cta: "Let's go!",
    postCompletionCta: 'Show Again',
    action: () => {
      showFirstSendDialog.value = true
    },
    completionAction: () => {
      showFirstSendDialog.value = false
      hasViewedFirstSend.value = true
      mp.track('Onboarding Action', {
        type: 'action',
        name: 'checklist',
        action: 'step-completed',
        stepName: 'first send'
      })
    },
    completed: hasViewedFirstSend.value,
    icon: CloudArrowUpIcon
  },
  {
    title: 'Enable Multiplayer 📢',
    blurb: 'Share your project with your colleagues!',
    active: false,
    cta: "Let's go!",
    postCompletionCta: 'Invite Again',
    action: () => {
      showServerInviteDialog.value = true
      //TODO: modify server invite dialog to include searchable project dropdown
    },
    completionAction: () => {
      showServerInviteDialog.value = false
      hasSharedProject.value = true
      mp.track('Onboarding Action', {
        type: 'action',
        name: 'checklist',
        action: 'step-completed',
        stepName: 'first share'
      })
    },
    completed: hasSharedProject.value,
    icon: ShareIcon
  }
])

const activateStep = (idx: number) => {
  steps.value.forEach((s, index) => (s.active = idx === index))
}

const markComplete = (idx: number) => {
  steps.value[idx].completed = true
  steps.value[idx].active = false
  steps.value[idx].completionAction()
  mp.track('Onboarding Action', {
    type: 'action',
    name: 'checklist',
    action: 'mark-complete',
    step: idx,
    status: getStatus()
  })
  activateStep(idx + 1)
}

const goToFirstUncompletedStep = () => {
  const firstNonCompleteStepIndex = steps.value.findIndex((s) => s.completed === false)
  mp.track('Onboarding Action', {
    type: 'action',
    name: 'checklist',
    action: 'goto-uncompleted-step',
    status: getStatus()
  })
  activateStep(firstNonCompleteStepIndex)
}

const allCompleted = computed(() => steps.value.every((step) => step.completed))

const closeChecklist = () => {
  hasCompletedChecklistV1.value = true
}

const dismissChecklist = () => {
  hasDismissedChecklistTime.value = Date.now().toString()
  emit('dismiss')
  mp.track('Onboarding Action', {
    type: 'action',
    name: 'checklist',
    action: 'dismiss',
    status: getStatus()
  })
}

const dismissChecklistForever = () => {
  hasDismissedChecklistForever.value = true
  emit('dismiss')
  mp.track('Onboarding Action', {
    type: 'action',
    name: 'checklist',
    action: 'dismiss-forever',
    status: getStatus()
  })
}

goToFirstUncompletedStep()
</script>
