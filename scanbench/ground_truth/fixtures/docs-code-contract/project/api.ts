export type User = { id: string; email: string };

export async function getUser(client: { get(path: string): Promise<User> }, id: string): Promise<User> {
  if (!id.trim()) {
    throw new Error('id is required');
  }
  return client.get(`/api/v2/users/${encodeURIComponent(id)}`);
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}
