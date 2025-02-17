import { wait } from '@speckle/shared'
import { Meta, StoryObj } from '@storybook/vue3'
import FormSelectBase from '~~/src/components/form/select/Base.vue'
import { isRequired } from '~~/src/helpers/common/validation'

type FakeItemType = { id: string; name: string }

type StoryType = StoryObj<
  Record<string, unknown> & {
    'update:modelValue': (val: FakeItemType) => void
  }
>

const fakeItems: FakeItemType[] = [
  {
    id: '1',
    name: 'Rocky Balboa'
  },
  {
    id: '2',
    name: 'Bozo the Clown'
  },
  {
    id: '3',
    name: `Some jabroni with a super very long name, I mean look at it, it's way too long for a select box!`
  },
  {
    id: '4',
    name: 'Miss America 1987'
  },
  {
    id: '5',
    name: 'Brad Pitt'
  },
  {
    id: '6',
    name: 'Kevin McCallister'
  },
  {
    id: '7',
    name: 'Rickety Cricket'
  },
  {
    id: '8',
    name: 'Master Chief'
  }
]

export default {
  component: FormSelectBase,
  parameters: {
    docs: {
      description: {
        component: 'Base component for implementing various kinds of select boxes.'
      }
    }
  },
  argTypes: {
    'update:modelValue': {
      type: 'function',
      action: 'v-model'
    },
    'nothing-selected': {
      type: 'string',
      description: 'Slot for rendering selectbox contents when nothing is selected'
    },
    'something-selected': {
      type: 'string',
      description: 'Slot for rendering selectbox contents when something is selected'
    },
    option: {
      type: 'string',
      description: 'Slot for rendering each option'
    },
    filterPredicate: {
      type: 'function'
    },
    getSearchResults: {
      type: 'function'
    },
    disabled: {
      type: 'boolean'
    },
    buttonStyle: {
      options: ['base', 'simple'],
      control: { type: 'select' }
    }
  }
} as Meta

export const Default: StoryType = {
  render: (args, ctx) => ({
    components: { FormSelectBase },
    setup: () => {
      return { args }
    },
    template: `
      <div class="flex justify-center h-72">
        <FormSelectBase v-bind="args" class="max-w-xs w-full" @update:modelValue="onModelUpdate"/>
      </div>
    `,
    methods: {
      onModelUpdate(val: FakeItemType) {
        args['update:modelValue'](val)
        ctx.updateArgs({ ...args, modelValue: val })
      }
    }
  }),
  args: {
    multiple: false,
    items: fakeItems,
    modelValue: undefined,
    search: false,
    filterPredicate: (val: FakeItemType, search: string) =>
      val.name.toLowerCase().includes(search.toLowerCase()),
    getSearchResults: undefined,
    searchPlaceholder: 'Search',
    label: 'Choose an item',
    showLabel: false,
    by: 'name',
    name: 'example',
    clearable: true,
    buttonStyle: 'base',
    disabled: false
  }
}

export const WithLabel: StoryType = {
  ...Default,
  args: {
    ...Default.args,
    showLabel: true
  }
}

export const WithLabelAndHelp: StoryType = {
  ...Default,
  args: {
    ...Default.args,
    showLabel: true,
    help: 'Some help text'
  }
}

export const Tinted: StoryType = {
  ...Default,
  args: {
    ...Default.args,
    buttonStyle: 'tinted'
  }
}

export const LimitedWidth: StoryType = {
  ...Default,
  render: (args, ctx) => ({
    components: { FormSelectBase },
    setup: () => {
      return { args }
    },
    template: `
      <div class="flex justify-center h-72 w-44">
        <FormSelectBase v-bind="args" class="max-w-xs w-full" @update:modelValue="onModelUpdate"/>
      </div>
    `,
    methods: {
      onModelUpdate(val: FakeItemType) {
        args['update:modelValue'](val)
        ctx.updateArgs({ ...args, modelValue: val })
      }
    }
  })
}

export const WithCustomSlots: StoryType = {
  render: (args, ctx) => ({
    components: { FormSelectBase },
    setup: () => {
      return { args }
    },
    template: `
      <div class="flex justify-center h-72">
        <FormSelectBase v-bind="args" class="max-w-xs w-full" @update:modelValue="onModelUpdate">
          <template #nothing-selected>{{ args['nothing-selected'] }}</template>
          <template #something-selected>{{ args['something-selected'] }}</template>
          <template #option>{{ args['option'] }}</template>
        </FormSelectBase>
      </div>
    `,
    methods: {
      onModelUpdate(val: FakeItemType) {
        args['update:modelValue'](val)
        ctx.updateArgs({ ...args, modelValue: val })
      }
    }
  }),
  args: {
    ...Default.args,
    'nothing-selected': 'NOTHING SELECTED SLOT',
    'something-selected': 'SOMETHING SELECTED SLOT',
    option: 'OPTION SLOT'
  },
  parameters: {
    docs: {
      description: {
        story: 'Use slots to change how various aspects render'
      }
    }
  }
}

export const Disabled: StoryType = {
  ...Default,
  args: {
    ...Default.args,
    disabled: true
  }
}

export const WithValidation: StoryType = {
  render: (args, ctx) => ({
    components: { FormSelectBase },
    setup: () => {
      return { args }
    },
    template: `
      <div class="flex justify-center h-72">
        <FormSelectBase v-bind="args" class="max-w-xs w-full" @update:modelValue="onModelUpdate" validate-on-mount/>
      </div>
    `,
    methods: {
      onModelUpdate(val: FakeItemType) {
        args['update:modelValue'](val)
        ctx.updateArgs({ ...args, modelValue: val })
      }
    }
  }),
  args: {
    multiple: false,
    items: fakeItems,
    modelValue: undefined,
    search: false,
    filterPredicate: (val: FakeItemType, search: string) =>
      val.name.toLowerCase().includes(search.toLowerCase()),
    searchPlaceholder: 'Search',
    label: 'Item',
    showLabel: true,
    by: 'name',
    rules: [isRequired],
    help: 'This is a random help message',
    name: 'example-2'
  }
}

export const WithFilter: StoryType = {
  ...Default,
  args: {
    ...Default.args,
    search: true
  }
}

export const WithAsyncSearch: StoryType = {
  ...WithFilter,
  args: {
    ...WithFilter.args,
    items: undefined,
    filterPredicate: undefined,
    getSearchResults: async (search: string): Promise<FakeItemType[]> => {
      const items = fakeItems.filter((val) =>
        val.name.toLowerCase().includes(search.toLowerCase())
      )
      await wait(2000)
      return items
    }
  }
}

export const Empty: StoryType = {
  ...WithAsyncSearch,
  args: {
    ...WithAsyncSearch.args,
    getSearchResults: () => []
  }
}

export const Simple: StoryType = {
  ...Default,
  args: {
    ...Default.args,
    buttonStyle: 'simple'
  }
}
