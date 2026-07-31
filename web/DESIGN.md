# Lazy Balancer V2 Web Design System

## 1. Atmosphere & Identity

A compact, trustworthy operations console. The signature is restrained blue interaction color over quiet gray surfaces, with information density carried by tables, labels, and semantic status colors rather than decoration.

## 2. Color

The canonical palette is defined by CSS variables in `src/styles/main.css`: `--primary`, `--primary-hover`, `--primary-bg`, semantic status colors, text roles, borders, and three surface levels. Element Plus components inherit the same semantic roles. New UI must use these variables or Element Plus semantic props rather than raw colors.

## 3. Typography

- Primary: system UI stack from `src/styles/main.css`.
- Mono: `ui-monospace`, SFMono-Regular, Menlo, Monaco, Consolas, monospace.
- Page title: 18px/600; card title: 14px/600; form and table body: 13-14px; hints and metadata: 12px.
- Body text must not be smaller than 12px in the dense administration interface.

## 4. Spacing & Layout

- Base unit: 4px.
- Compact: 4px; inline: 8px; form/content: 12px; card rhythm: 20px; generous: 24px.
- Settings pages use vertical stacks with 20px gaps and Element Plus cards.
- Tables use intrinsic column sizing with explicit minimum widths and fixed action columns. Long unbroken values truncate or wrap without expanding the page.
- The application shell owns page scrolling; dialogs own their internal overflow.

## 5. Components

### Settings Card
- Element Plus card with icon/title header and optional right-side action.
- Uses 8px title gap, 14px/600 title, and existing semantic tokens.

### Data Table
- Element Plus table with semantic tags, `link`/`small` row actions, fixed right action column, and an explicit empty state.
- Long strings use ellipsis plus a tooltip; URL values use a semantic primary link and open in a new tab with `noopener noreferrer`.

### Form Dialog
- Element Plus dialog sized with `min(<desktop width>, 92vw)` and a labeled form.
- Validation errors render below fields; helper text uses the 12px muted text pattern.
- Footer actions are “取消” then primary “保存”; saving disables closing actions and shows loading feedback.

## 6. Motion & Interaction

Use Element Plus interaction transitions. Every interactive control retains hover, active, focus, disabled, and loading states. Do not add decorative motion.

## 7. Depth & Surface

Mixed strategy inherited from Element Plus: subtle borders for cards/tables/forms and restrained shadows only for elevated overlays such as dialogs and popovers. Radii use `--radius-sm` through `--radius-xl`.

## 8. Accessibility Constraints & Accepted Debt

- Target WCAG 2.2 AA with keyboard-reachable controls and visible Element Plus focus states.
- Links must remain real anchors with discernible text and safe new-window attributes.
- Form inputs always have visible labels, contextual helper text, and inline errors.
- Accepted debt: the existing settings tables may horizontally scroll on narrow screens because their dense operational content cannot reflow without losing row relationships.
