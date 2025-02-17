<template>
  <div class="relative flex items-start">
    <div class="flex h-6 items-center">
      <!-- eslint-disable-next-line vuejs-accessibility/form-control-has-label -->
      <input
        :id="finalId"
        :checked="finalChecked"
        :aria-describedby="descriptionId"
        :name="name"
        :value="checkboxValue"
        :disabled="disabled"
        type="checkbox"
        class="h-4 w-4 rounded text-primary focus:ring-primary bg-foundation disabled:cursor-not-allowed disabled:bg-disabled disabled:text-disabled-2"
        :class="computedClasses"
        v-bind="$attrs"
        @change="onChange"
      />
    </div>
    <div class="ml-2 text-sm" style="padding-top: 2px">
      <label
        :for="finalId"
        class="font-medium text-foreground"
        :class="{ 'sr-only': hideLabel }"
      >
        <span>{{ title }}</span>
        <span v-if="showRequired" class="text-danger ml-1">*</span>
      </label>
      <p v-if="descriptionText" :id="descriptionId" :class="descriptionClasses">
        {{ descriptionText }}
      </p>
    </div>
  </div>
</template>
<script setup lang="ts">
import { RuleExpression, useField } from 'vee-validate'
import { PropType, computed, ref } from 'vue'
import { Optional } from '@speckle/shared'
import { nanoid } from 'nanoid'

/**
 * Troubleshooting:
 * - If clicking on the checkbox doesn't do anything, check if any of its ancestor elements
 * have a @click.prevent on them anywhere.
 * - If you're not using the checkbox in a group, it's suggested that you set :value="true",
 * so that a v-model attached to the checkbox will be either 'true' or 'undefined' depending on the
 * checked state
 */

type ValueType = Optional<string | true> | string[]

defineOptions({
  inheritAttrs: false
})

const props = defineProps({
  /**
   * Input name/id. In a checkbox group, all checkboxes must have the same name and different values.
   */
  name: {
    type: String,
    required: true
  },
  /**
   * Whether the input is disabled
   */
  disabled: {
    type: Boolean,
    default: false
  },
  /**
   * Set label text
   */
  label: {
    type: String as PropType<Optional<string>>,
    default: undefined
  },
  /**
   * Help text
   */
  description: {
    type: String as PropType<Optional<string>>,
    default: undefined
  },
  /**
   * Whether to inline the help description
   */
  inlineDescription: {
    type: Boolean,
    default: false
  },
  /**
   * vee-validate validation rules
   */
  rules: {
    type: [String, Object, Function, Array] as PropType<RuleExpression<ValueType>>,
    default: undefined
  },
  /**
   * vee-validate validation() on component mount
   */
  validateOnMount: {
    type: Boolean,
    default: false
  },
  /**
   * Whether to show the red "required" asterisk
   */
  showRequired: {
    type: Boolean,
    default: false
  },
  /**
   * Checkbox group's value
   */
  modelValue: {
    type: [String, Boolean] as PropType<ValueType | false>,
    default: undefined
  },
  /**
   * Checkbox's own value. If it is checked, modelValue will include this value (amongst any other checked values from the same group).
   * If not set will default to 'name' value.
   */
  value: {
    type: [String, Boolean] as PropType<Optional<string | true>>,
    default: true
  },
  /**
   * HTML ID to use, must be globally unique. If not specified, a random ID will be generated. One is necessary to properly associate the label and checkbox.
   */
  id: {
    type: String as PropType<Optional<string>>,
    default: undefined
  },
  hideLabel: {
    type: Boolean,
    default: false
  }
})

const generateRandomId = (prefix: string) => `${prefix}-${nanoid()}`

defineEmits<{
  (e: 'update:modelValue', val: ValueType): void
}>()

const checkboxValue = computed(() => props.value || props.name)

const {
  checked: finalChecked,
  errorMessage,
  handleChange
} = useField<ValueType>(props.name, props.rules, {
  validateOnMount: props.validateOnMount,
  type: 'checkbox',
  checkedValue: checkboxValue,
  initialValue: props.modelValue || undefined
})

const onChange = (e: unknown) => {
  if (props.disabled) return
  handleChange(e)
}

const title = computed(() => props.label || props.name)

const computedClasses = computed((): string => {
  return errorMessage.value ? 'border-danger-lighter' : 'border-foreground-4 '
})

const descriptionText = computed(() => props.description || errorMessage.value)
const descriptionId = computed(() => `${props.name}-description`)
const descriptionClasses = computed((): string => {
  const classParts: string[] = []

  if (props.inlineDescription) {
    classParts.push('inline ml-2')
  } else {
    classParts.push('block')
  }

  if (errorMessage.value) {
    classParts.push('text-danger')
  } else {
    classParts.push('text-foreground-2')
  }

  return classParts.join(' ')
})

const implicitId = ref<Optional<string>>(generateRandomId('checkbox'))
const finalId = computed(() => props.id || implicitId.value)
</script>
