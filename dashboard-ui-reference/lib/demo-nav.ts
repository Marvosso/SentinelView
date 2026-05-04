/** Rich demo presets (mock client + activity + issues). */

export function isRichDemo(demo: string | undefined | null): boolean {
  return demo === "client" || demo === "full";
}

/** Append `?demo=…` so Operations pages stay on the same mock workspace. */
export function withDemoParam(path: string, demo: string | undefined | null): string {
  if (!isRichDemo(demo)) return path;
  const param = `demo=${demo}`;
  return path.includes("?") ? `${path}&${param}` : `${path}?${param}`;
}
