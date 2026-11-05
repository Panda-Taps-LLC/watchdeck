// The engine's own band, standing beneath the mod in a test: drawn when the
// mod hands the AbovePrompt site on with `next(e)`, counted so a test can
// tell whether the mod drew the band itself.

import type { On } from 'claude-code'

export function engineBand(on: On): { drawn: number } {
  const seen = { drawn: 0 }
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => {
    seen.drawn += 1
    const { Text } = $.ui.resolve(e)
    return <Text>engine band</Text>
  })
  return seen
}
