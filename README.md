# vault-desktop

Desktop client for the personal digital vault project.

## Current phase

This phase provides:

- desktop repository scaffold
- PySide6 application shell
- API connectivity client
- simple status window
- login form
- in-memory session state
- config layer
- test scaffold

## Architecture notes

- desktop client is separate from the backend API
- local crypto and unlock flows will be added later
- current UI supports backend probing and login only
- session state is currently kept in memory only
