# vault-desktop

Desktop client for the personal digital vault project.

## Current phase

This phase provides:

- desktop repository scaffold
- PySide6 application shell
- API connectivity client
- login form
- in-memory session state
- post-login read-only dashboard fetches
- tabbed dashboard layout for credentials, notes, and files
- selected object detail fetches
- desktop-side authenticated service abstraction
- selection-driven dashboard lists
- local persistence for non-sensitive UI preferences
- vault gateway abstraction for current and future backend contracts
- config layer
- test scaffold

## Architecture notes

- desktop client is separate from the backend API
- local crypto and unlock flows will be added later
- current UI supports backend probing, login, logout, list fetches, and detail fetches
- session state is currently kept in memory only
- the desktop service layer centralizes session-aware backend access
- vault reads now go through a gateway abstraction
- the current gateway still uses backend dev routes
- only non-sensitive desktop preferences are persisted locally
