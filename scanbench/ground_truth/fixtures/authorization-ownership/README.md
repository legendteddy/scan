# Authorization ownership fixture

A small service contains a realistic object-level authorization defect: an authenticated user may delete any document because ownership is never checked. The same file includes a parameterized database lookup as a negative SQL-injection control. Production identity-provider MFA configuration is intentionally absent and must remain unknown from repository evidence.
