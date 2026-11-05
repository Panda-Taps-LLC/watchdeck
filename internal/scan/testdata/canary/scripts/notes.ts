export async function pull(url: string) {
  const r = await fetch(url);
  return r.text();
}
