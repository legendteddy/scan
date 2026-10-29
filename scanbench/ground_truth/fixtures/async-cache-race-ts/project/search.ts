type Result = { id: string; label: string };

let latestQuery = '';
let latestResults: Result[] = [];

export async function search(query: string): Promise<Result[]> {
  latestQuery = query;
  const params = new URLSearchParams({ q: query });
  const response = await fetch(`/api/search?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`search failed: ${response.status}`);
  }
  const results = (await response.json()) as Result[];
  latestResults = results;
  return latestResults;
}

export function currentSearch(): { query: string; results: Result[] } {
  return { query: latestQuery, results: latestResults };
}
