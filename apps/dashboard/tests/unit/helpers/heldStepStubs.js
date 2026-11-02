import { createElement as h } from 'react';

// Stands in for a step that waits for outside work: a Poll button re-reads the
// summary, and Switch platform changes the saved platform.
export function stubOf(id) {
  const switchPlatform = ctx => async () => {
    await ctx.controller.update(s => ({
      progress: {
        ...s.progress,
        certops: {
          ...s.progress.certops,
          infrastructure: 'kubernetes',
          clusterId: 'c1',
        },
      },
    }));
    await ctx.refresh();
  };
  return function Stub({ ctx }) {
    return h(
      'div',
      { 'data-testid': `stub-${id}` },
      h(
        'button',
        { type: 'button', onClick: () => ctx.refresh() },
        `Poll ${id}`
      ),
      h(
        'button',
        { type: 'button', onClick: switchPlatform(ctx) },
        `Switch platform ${id}`
      )
    );
  };
}
