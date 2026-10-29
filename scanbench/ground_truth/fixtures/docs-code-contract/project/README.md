# User client

`getUser(id)` calls `/api/v1/users/:id`.

If `id` is empty, `getUser` returns `null` and does not throw.

`normalizeEmail(value)` trims surrounding whitespace and lowercases the address before use.
