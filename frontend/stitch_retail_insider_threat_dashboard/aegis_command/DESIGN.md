# Design System Document: Cyber Dark SOC & UEBA

## 1. Overview & Creative North Star
**Creative North Star: "The Sentinel’s Lens"**

This design system is engineered to move beyond the clichéd "hacker" aesthetic into a realm of high-end, mission-critical sophistication. We are building a "Sentinel’s Lens"—a visual framework that prioritizes rapid cognitive processing and authoritative clarity. 

Unlike standard dashboards that rely on rigid boxes and heavy borders, this system utilizes **Tonal Layering** and **Luminous Accents** to create a sense of depth and focus. We break the "template" look by using intentional white space (negative space), asymmetrical data layouts, and high-contrast typography scales that make the data feel like a live, breathing organism rather than a static table.

---

## 2. Colors & Surface Philosophy
The palette is rooted in the deep void of a Security Operations Center (SOC), using luminosity to represent threat levels.

### The "No-Line" Rule
To achieve a premium feel, **1px solid borders are prohibited for sectioning.** Boundaries between major UI sections must be defined solely through background color shifts. A `surface-container-low` section sitting on a `surface` background provides all the separation necessary for a sophisticated eye.

### Surface Hierarchy & Nesting
Depth is achieved through the physical metaphor of "stacked glass." 
- **Surface (`#101319`):** The base "floor" of the application.
- **Surface-Container-Low (`#191c22`):** Large structural areas (e.g., Sidebar, Main Content area).
- **Surface-Container-High (`#272a31`):** Active cards, data modules, and interactive elements.
- **Surface-Container-Highest (`#32353c`):** Hover states and pop-overs.

### The "Glass & Gradient" Rule
Floating elements (Modals, Tooltips, Context Menus) should utilize **Glassmorphism**. Use `surface-bright` at 60% opacity with a `20px` backdrop-blur. 
Main CTAs and critical alert headers should use subtle linear gradients (e.g., `primary` to `primary_container` at a 135° angle) to provide a "spectral" depth that flat colors lack.

---

## 3. Typography
The system uses a dual-font strategy to balance editorial elegance with technical precision.

- **Headlines (Inter):** High-contrast, modern sans-serif. Used for "Display" and "Headline" roles. It conveys authority and provides a clean break from dense data.
- **Data & Labels (Space Grotesk):** A geometric sans with a technical "flavor." While the original request suggested monospaced fonts, we utilize **Space Grotesk** for body and labels to maintain a high-end editorial feel, reserving true monospaced fonts (`Roboto Mono`) strictly for raw log streams and CLI inputs.

**Scale Highlights:**
- **Display LG (3.5rem):** Reserved for high-level "At a Glance" metrics (e.g., Total Threats).
- **Title SM (1rem):** The workhorse for card headers and navigation.
- **Label SM (0.6875rem):** All-caps with 0.05em tracking for metadata and timestamps.

---

## 4. Elevation & Depth
In this system, light is the primary architect of space.

### The Layering Principle
Do not use drop shadows to indicate "lifting" a card off a background. Instead, place a `surface-container-lowest` card on a `surface-container-low` background. This "inverse lift" creates a recessed, high-tech instrument feel.

### Ambient Shadows
When a floating element (like a context menu) is required, use **Ambient Shadows**:
- **Blur:** 32px to 64px.
- **Opacity:** 8%.
- **Color:** Use a tinted version of `primary` (`#a4e6ff`) rather than black to simulate the glow of the screen reflecting off the UI surface.

### The "Ghost Border" Fallback
If accessibility requires a container boundary, use a **Ghost Border**: `outline_variant` at 15% opacity. It should be felt, not seen.

---

## 5. Components

### High-Tech Cards
Cards must never have visible dividers. Group content using vertical spacing (16px or 24px).
- **Risk Indicator:** Cards representing users/entities should feature a 2px "Glow Strip" on the left edge using the risk color tokens (`secondary` for Low, `tertiary` for Critical).

### Primary Buttons
- **Style:** No solid background. Use a `ghost-border` with `primary` text.
- **State:** On hover, fill with a 10% opacity `primary` tint and add a subtle `primary` outer glow (4px blur).

### Interactive Data Tables
- **Layout:** Remove all vertical lines. Use `surface-container-low` for the header and `surface` for the rows. 
- **Row Interaction:** On hover, shift the row background to `surface-container-high`.
- **UEBA Scoring:** Display risk scores in `label-md` with a high-saturation background (`error_container` for Critical) but keep the text `on_error_container` for maximum legibility.

### Sidebar Navigation
- **Aesthetic:** Minimalist and narrow. 
- **Active State:** Indicate the active route with a `primary` color glow-dot (4px) next to the icon, rather than a bulky background highlight.

---

## 6. Do’s and Don’ts

### Do
- **Use "Space as a Divider":** Rely on the spacing scale to separate data clusters.
- **Embrace Asymmetry:** In the SOC dashboard, allow the most critical alert card to take up 60% of the width, with smaller metrics flanking it.
- **Prioritize the "On-Surface" Palette:** Use `on_surface_variant` for secondary data to reduce visual noise.

### Don’t
- **Don't use 100% white (#FFFFFF):** It causes eye strain in dark environments. Use `on_surface` (`#e1e2eb`).
- **Don't use rounded corners > 8px:** This is a mission-control tool, not a consumer social app. Keep corners at `sm` (2px) or `md` (6px) to maintain a "machined" look.
- **Don't use "Alert Red" for everything:** Reserve `Alert Red` (#FF3131) strictly for data points requiring immediate human intervention. Use `tertiary` tokens for UI-related errors.