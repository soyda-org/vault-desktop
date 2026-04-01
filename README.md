# vault-desktop

Desktop client for the personal digital vault project.

## Current phase

This phase provides:

- desktop repository scaffold
- PySide6 application shell
- API connectivity client
- login form
- in-memory session state
- authenticated vault gateway
- automatic refresh-token rotation handling
- retry-once flow after HTTP 401 on vault reads
- post-login read-only dashboard fetches
- tabbed dashboard layout for credentials, notes, and files
- selected object detail fetches
- desktop-side authenticated service abstraction
- selection-driven dashboard lists
- local persistence for non-sensitive UI preferences
- config layer
- test scaffold

## Architecture notes

- desktop client is separate from the backend API
- local crypto and unlock flows will be added later
- current UI supports backend probing, login, logout, list fetches, and detail fetches
- session state is currently kept in memory only
- vault reads go through an authenticated gateway abstraction
- when a vault read gets HTTP 401, the desktop service attempts one refresh and retries once
- both access token and refresh token are rotated in memory after a successful refresh
- only non-sensitive desktop preferences are persisted locally

<!-- BEGIN:OPENAI_DESKTOP_AUTH_UX -->
## Signup, login, and recovery UX

The desktop app now follows this model:

1. **Sign Up** performs local vault bootstrap and sends the full register payload expected by the API.
2. The recovery key is shown **once** during signup and must be saved outside Git.
3. **Login** remains account authentication via identifier + password.
4. **Recovery** is treated as a vault-scoped action, not as a global substitute for login.

Probe API, Login, and Sign Up are intended to remain responsive even when the backend is slow,
so network-bound work should stay off the UI thread.
<!-- END:OPENAI_DESKTOP_AUTH_UX -->
