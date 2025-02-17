import { userEvent, within } from '@storybook/testing-library'
import { Meta, StoryObj } from '@storybook/vue3'
import { wait } from '@speckle/shared'
import FormCardButton from '~~/src/components/form/CardButton.vue'
import { VuePlayFunction } from '~~/src/stories/helpers/storybook'

type StoryType = StoryObj<
  Record<string, unknown> & {
    'update:modelValue': (val: boolean) => void
  }
>

export default {
  component: FormCardButton,
  argTypes: {
    default: {
      type: 'string',
      description: 'Default slot holds button contents'
    },
    click: {
      action: 'click',
      type: 'function'
    },
    'update:modelValue': {
      action: 'update:modelValue',
      type: 'function'
    }
  },
  parameters: {
    docs: {
      description: {
        component: 'A card button that supports a toggled/selected state'
      }
    }
  }
} as Meta

const clickPlayBuilder: (rightClick?: boolean) => VuePlayFunction =
  (rightClick) =>
  async ({ canvasElement }) => {
    const canvas = within(canvasElement)

    userEvent.click(canvas.getByRole('button'), rightClick ? { button: 2 } : undefined)

    await wait(500)

    userEvent.click(canvas.getByRole('button'), rightClick ? { button: 2 } : undefined)

    userEvent.tab()
  }

export const Default: StoryType = {
  render: (args, ctx) => ({
    components: { FormCardButton },
    setup() {
      return { args }
    },
    template: `<FormCardButton v-bind="args" @click="args.click" @update:modelValue="onModelUpdate">{{ args.default || 'Text' }}</FormCardButton>`,
    methods: {
      onModelUpdate(val: boolean) {
        args['update:modelValue'](val)
        ctx.updateArgs({ ...args, modelValue: val })
      }
    }
  }),
  play: clickPlayBuilder(),
  args: {
    default: 'Architecture',
    disabled: false,
    modelValue: false
  }
}

export const Disabled: StoryType = {
  ...Default,
  args: {
    disabled: true
  }
}

export const Selected: StoryType = {
  ...Default,
  play: clickPlayBuilder(true),
  args: {
    modelValue: true
  }
}
