export interface CompositeTrigger {
  when: string[];
  strategies: string[];
}

export const COMPOSITE_TRIGGERS: CompositeTrigger[] = [
  {
    when: ["tag", "event"],
    strategies: ["custom-elements", "interaction-events", "dom-clobbering"]
  },
  {
    when: ["keyword", "paren"],
    strategies: ["confirm-prompt-print", "paren-bypass-cascade", "jsfuck"]
  },
  {
    when: ["angle", "tag"],
    strategies: ["html-entity-angle", "svg-decode", "href-data-uri"]
  },
  {
    when: ["csp", "script"],
    strategies: ["dom-clobbering", "window.name", "svg-upload"]
  }
];

