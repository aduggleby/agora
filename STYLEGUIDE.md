# Agora Style Guide — "Warm Craft"

This document defines the visual design system for Agora. All UI changes must follow these guidelines.

## Design Philosophy

Warm Craft is **editorial, approachable, and human**. It avoids clinical SaaS aesthetics in favor of a paper-like palette and serif display headlines that feel authored, not generated. The design prioritizes **clarity and calm** — every element has a clear purpose and generous space to breathe.

**Key principles:**

- UX over decoration. Every visual choice serves comprehension or usability.
- Warmth without excess. The palette is warm but restrained — no gradients, no glow.
- Typography carries personality. The serif display font is the signature; body text stays neutral.

## Color Palette

All colors are defined as Tailwind CSS v4 theme tokens in `src/Agora.Web/Styles/tailwind.css`.

| Token | Hex | Usage |
|---|---|---|
| `cream` | `#FAF7F2` | Page background |
| `cream-dark` | `#F0EBE3` | Secondary backgrounds, input backgrounds |
| `ink` | `#1A1614` | Primary text |
| `ink-light` | `#5C534A` | Secondary text, descriptions |
| `ink-muted` | `#9B9189` | Tertiary text, labels, placeholders |
| `terra` | `#C4663A` | Primary accent — buttons, links, active states |
| `terra-light` | `#E8A17D` | Accent borders, subtle highlights |
| `terra-wash` | `#FFF3ED` | Accent background wash (notifications, avatars) |
| `sage` | `#5B7A5E` | Success/active indicator |
| `sage-wash` | `#EDF5EE` | Success background |
| `border` | `#E5DFD7` | Borders, dividers, card outlines |
| `danger` | `#B91C1C` | Destructive actions |
| `danger-wash` | `#FEF2F2` | Danger background |

### Usage Rules

- **Primary actions** (create, submit): `bg-terra text-white`
- **Secondary actions** (save template): `bg-ink text-white`
- **Destructive actions**: `text-danger` for text, never `bg-danger` on buttons
- **Links**: `text-terra` with `hover:underline`
- **Form inputs**: `bg-cream border-border` with `focus:border-terra focus:ring-1 focus:ring-terra/20`
- **Cards**: `bg-white border border-border rounded-2xl`
- **Message banners**: `bg-terra-wash border-terra-light/30`

## Typography

### Fonts

| Role | Font | Source |
|---|---|---|
| Display (headings) | **Instrument Serif** | Google Fonts |
| Body (everything else) | **DM Sans** | Google Fonts |

Both are loaded via Google Fonts in the HTML `<head>`:

```html
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet">
```

### Usage

- Page titles: `font-display text-3xl` or `text-4xl`, use italic (`italic`) for emphasis
- Section headings: `font-display text-xl`
- Form labels: `text-xs font-medium text-ink-muted uppercase tracking-wider`
- Body text: default font (DM Sans), `text-sm`
- Small/meta text: `text-xs text-ink-muted`

### Do Not Use

- Inter, Roboto, Arial, or system-ui as display fonts
- Font sizes larger than `text-4xl` in app UI (reserve for marketing)
- Bold body text for emphasis — use `text-terra` or `font-medium` instead

## Layout

- **Max width**: `max-w-5xl` (64rem / 1024px), centered with `mx-auto px-6`
- **Page structure**: Header (border-bottom) → Main content → Footer (border-top)
- **Cards**: `bg-white rounded-2xl border border-border p-6`
- **Grid**: Use `grid grid-cols-1 sm:grid-cols-2 gap-4` for form fields
- **Spacing between sections**: `mb-10` (2.5rem)

## Components

### Buttons

```html
<!-- Primary -->
<button class="px-6 py-2.5 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors">
  Create share link
</button>

<!-- Secondary -->
<button class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-cream-dark transition-colors">
  Cancel
</button>
```

### Form Inputs

```html
<input class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
```

- Always pair with a label: `<label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">`
- Selects use the same classes plus `appearance-none`
- Textareas add `resize-y`

### Status Indicators

- Active: `<span class="inline-block w-2 h-2 rounded-full bg-sage"></span>`
- Inactive/expired: `<span class="inline-block w-2 h-2 rounded-full bg-ink-muted"></span>`
- Expiry badges: `text-xs bg-sage-wash text-sage px-2 py-0.5 rounded-md` (safe) or `bg-terra-wash text-terra` (expiring soon)

### Navigation

- Header is a flex row with logo left, nav links + user right
- Logo: terra square icon + "Agora" in Instrument Serif
- Nav links: `text-sm text-ink-muted hover:text-ink transition-colors`
- User avatar: `w-7 h-7 rounded-full bg-terra-wash text-terra text-xs font-medium`

### Message Banner

For flash messages (success, errors, info):

```html
<div class="mb-6 px-4 py-3 bg-terra-wash border border-terra-light/30 rounded-xl text-sm text-ink-light">
  Message text here
</div>
```

## Share Landing Page

The public share page (`/s/{token}`) uses **inline CSS** (not Tailwind) so it works without the CSS bundle. It follows the same Warm Craft palette via CSS custom properties. Key elements:

- Centered card on cream background
- Instrument Serif heading
- File info in a bordered cream panel
- Single terra-colored download button
- "Shared via Agora" footer attribution

## Build Process

Tailwind CSS v4 is used with the CLI compiler:

```bash
cd src/Agora.Web
npm run tailwind:build    # one-time build
npm run tailwind:watch    # watch for changes
```

Source: `src/Agora.Web/Styles/tailwind.css`
Output: `src/Agora.Web/wwwroot/css/site.css`

The output CSS is committed and served as a static file via `app.UseStaticFiles()`.

## Accessibility

- All form inputs have associated `<label>` elements
- Color contrast meets WCAG AA for body text (ink on cream, white on terra)
- Interactive elements have visible focus states (`focus:border-terra focus:ring-1`)
- No animations that could trigger motion sensitivity (animations are CSS-only and subtle)
