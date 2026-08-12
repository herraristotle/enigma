import { MutationComposer } from "../../core/engines/mutation/composer.ts";
import { createSession } from "../../core/runner/session-store.ts";

async function main(): Promise<void> {
  const [target, parameter] = process.argv.slice(2);
  const composer = new MutationComposer("html_content");
  const session = createSession(target || "", parameter || "", "html_content", composer.exportState());
  console.log(JSON.stringify({
    sessionId: session.sessionId,
    target: session.target,
    parameter: session.parameter,
    context: session.context,
    knowledge: session.knowledge
  }, null, 2));
}

void main();
