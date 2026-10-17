// Module resolve hook: `@tinfoilsh/verifier` -> fakeTinfoilVerifier.mjs.
const FAKE = new URL('./fakeTinfoilVerifier.mjs', import.meta.url).href;

export async function resolve(specifier, context, next) {
  if (specifier === '@tinfoilsh/verifier') return { url: FAKE, shortCircuit: true };
  return next(specifier, context);
}
