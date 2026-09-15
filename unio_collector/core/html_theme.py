"""Neutral HTML theme shared by local restoration and application reports."""

from __future__ import annotations


def render_html_theme_tokens() -> str:
    """Return dependency-neutral Tevari Cloud / Unio HTML theme tokens."""
    return """
:root {
  /* Brand */
  --color-brand-teal: #008B91;
  --color-brand-cyan: #0CC5C5;
  --color-brand-cyan-soft: #69D0CF;

  /* Semantic accents */
  --color-accent-govern: #22C55E;
  --color-accent-automate: #F97316;

  /* Light theme */
  --color-bg-page: #F6F9FB;
  --color-bg-header: #FBFDFF;
  --color-bg-section: #EEF4F9;
  --color-bg-section-alt: #EAF1F7;
  --color-bg-section-secondary: #E9F0F5;

  --color-surface-primary: #FFFFFF;
  --color-surface-soft: #F1F8F9;
  --color-surface-hero: #F0F7FA;

  --color-border-soft: #D9E4EC;
  --color-border-strong: #B5C7CF;

  --color-text-primary: #061320;
  --color-text-strong: #020A15;
  --color-text-secondary: #3A4654;
  --color-text-muted: #56616D;

  /* CTA */
  --color-cta-primary: #007A80;
  --color-cta-primary-hover: #006B70;
  --color-cta-primary-text: #FFFFFF;

  /* Accessible status colours: distinct from the brand palette. */
  --color-status-critical: #B42318;
  --color-status-critical-text: #7A271A;
  --color-status-critical-surface: #FFF4ED;
  --color-status-warning: #F97316;
  --color-status-warning-text: #7C2D12;
  --color-status-warning-surface: #FFF7ED;
  --color-status-info: #007A80;
  --color-status-info-text: #006B70;
  --color-status-info-surface: #F1F8F9;
  --color-status-positive: #22C55E;
  --color-status-positive-text: #166534;
  --color-status-positive-surface: #F0FDF4;
  --color-status-unknown-text: #3A4654;
  --color-status-unknown-surface: #E9F0F5;

  /* Dark branded report surfaces */
  --color-dark-page: #020812;
  --color-dark-header: #020A15;
  --color-dark-section: #061320;
  --color-dark-hero-outer: #071220;
  --color-dark-section-alt: #0A1B2B;
  --color-dark-methodology: #0B1D2F;

  --color-dark-hero: #081D2D;
  --color-dark-card: #091B2C;
  --color-dark-cta: #092232;

  --color-dark-border-soft: #243746;
  --color-dark-border-strong: #314A58;

  --color-dark-text-primary: #F6F9FB;
  --color-dark-text-strong: #FFFFFF;
  --color-dark-text-secondary: #D1D8DD;
  --color-dark-text-muted: #97A0A9;
}
""".strip()
