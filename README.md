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
