# PROJECT KNOWLEDGE BASE: Lazy Balancer V2 (Frontend)

**Stack:** Vue 3, TypeScript, Vite, Pinia, Element Plus, Tailwind CSS

## OVERVIEW
The frontend is a single-page application (SPA) that provides a management interface for the Lazy Balancer backend. It handles authentication, real-time monitoring via ECharts, and Caddy configuration orchestration.

## STRUCTURE
```
./web/src/
├── components/    # Shared UI components (Layout, custom widgets)
├── stores/        # Pinia state management (auth, session)
├── utils/         # API clients, date helpers, validation logic
├── views/         # Page-level components (Dashboard, Nodes, Rules, etc.)
├── types/         # TypeScript interfaces and type definitions
└── styles/        # Global CSS and Tailwind configurations
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| API Integration | `src/utils/api.ts` | Axios instances and endpoint definitions |
| Global State | `src/stores/` | Auth state and current page tracking |
| Page Logic | `src/views/` | Individual feature implementations |
| Component Layout | `src/components/layout/` | Main application shell and navigation |
| Type Definitions | `src/types/index.ts` | Backend entity mappings (Rule, Node, User) |

## CONVENTIONS
- **Vue Style**: Composition API with `<script setup lang="ts">`.
- **Styling**: Tailwind CSS for layout, Element Plus for complex components.
- **State**: Pinia for cross-component state (e.g., authentication tokens).
- **Routing**: Custom page switching logic handled via `authStore.currentPage` in `App.vue`.

## NOTES
- **Authentication**: Token-based auth managed in `authStore`.
- **Visualization**: ECharts used for traffic and health metrics on the Dashboard.
- **API**: Communicates with the Go backend via REST API.
