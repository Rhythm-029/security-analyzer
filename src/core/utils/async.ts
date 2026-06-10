export async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  handler: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }

  const safeConcurrency = Math.max(1, Math.floor(concurrency));
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  const workers = Array.from({ length: Math.min(safeConcurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      results[currentIndex] = await handler(items[currentIndex], currentIndex);
    }
  });

  await Promise.all(workers);
  return results;
}
