<template>
  <LayoutDialog v-model:open="isOpen" max-width="md">
    <form @submit="onSubmit">
      <div class="flex flex-col space-y-4 text-foreground">
        <h1 class="h4 font-bold">Get your colleagues in!</h1>
        <p>
          Speckle will send a server invite link to the email(-s) below. You can also
          add a personal message if you want to. To add multiple e-mails, seperate them
          with commas.
        </p>
        <FormTextInput
          :custom-icon="EnvelopeIcon"
          name="emailsString"
          label="E-mail"
          placeholder="example@example.com, example2@example.com"
          :rules="[isRequired, isOneOrMultipleEmails]"
          :disabled="anyMutationsLoading"
        />
        <FormTextArea
          name="message"
          label="Message"
          :disabled="anyMutationsLoading"
          :rules="[isStringOfLength({ maxLength: 1024 })]"
          placeholder="Write an optional invitation message!"
        />
        <div
          class="grow flex flex-col space-y-4 sm:space-y-0 sm:flex-row sm:justify-between sm:items-center"
        >
          <div class="grow">
            <FormSelectProjects
              v-model="selectedProject"
              label="(Optional) Select project to invite to"
              class="w-full sm:w-60"
              owned-only
            />
          </div>
          <div class="flex justify-end">
            <FormButton text @click="isOpen = false">Cancel</FormButton>
            <FormButton submit :disabled="anyMutationsLoading">Send</FormButton>
          </div>
        </div>
      </div>
    </form>
  </LayoutDialog>
</template>
<script setup lang="ts">
import { EnvelopeIcon } from '@heroicons/vue/24/solid'
import { Optional } from '@speckle/shared'
import { useMutationLoading } from '@vue/apollo-composable'
import { useForm } from 'vee-validate'
import { FormSelectProjects_ProjectFragment } from '~~/lib/common/generated/gql/graphql'
import {
  isRequired,
  isOneOrMultipleEmails,
  isStringOfLength
} from '~~/lib/common/helpers/validation'
import { useMixpanel } from '~~/lib/core/composables/mp'
import { useInviteUserToProject } from '~~/lib/projects/composables/projectManagement'
import { useInviteUserToServer } from '~~/lib/server/composables/invites'

const emit = defineEmits<{
  (e: 'update:open', val: boolean): void
}>()

const props = defineProps<{
  open: boolean
}>()

const selectedProject = ref(undefined as Optional<FormSelectProjects_ProjectFragment>)

const { handleSubmit } = useForm<{ message?: string; emailsString: string }>()
const { mutate: inviteUserToServer } = useInviteUserToServer()
const inviteUserToProject = useInviteUserToProject()
const anyMutationsLoading = useMutationLoading()

const isOpen = computed({
  get: () => props.open,
  set: (newVal) => emit('update:open', newVal)
})

const mp = useMixpanel()
const onSubmit = handleSubmit(async (values) => {
  const emails = values.emailsString.split(',').map((i) => i.trim())
  const project = selectedProject.value

  const success = project
    ? await inviteUserToProject(
        project.id,
        emails.map((email) => ({
          email
        }))
      )
    : await inviteUserToServer(
        emails.map((email) => ({
          email,
          message: values.message
        }))
      )
  if (success) {
    isOpen.value = false
    selectedProject.value = undefined
    mp.track('Invite Action', {
      type: 'server invite',
      name: 'send',
      multiple: emails.length !== 1,
      count: emails.length,
      hasProject: !!project,
      to: 'email'
    })
  }
})
</script>
