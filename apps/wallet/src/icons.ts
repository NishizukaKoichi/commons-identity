const paths: Record<string, string> = {
  identity:
    '<path d="M12 3.4 19 7v5c0 4.7-2.9 7.7-7 9.3C7.9 19.7 5 16.7 5 12V7l7-3.6Z"/><path d="M9.3 12.1 11 13.8l3.8-4"/>',
  presentation:
    '<path d="M4 6.5h16v11H4z"/><path d="M8 10h4M8 13.5h7M16.5 9.5v4"/>',
  devices:
    '<rect x="5" y="3.5" width="14" height="17" rx="2"/><path d="M9 6h6M10 17.5h4"/>',
  recovery:
    '<path d="M7 9V7a5 5 0 0 1 10 0v2"/><rect x="4" y="9" width="16" height="11" rx="2"/><path d="M12 13v3"/>',
  receipts:
    '<path d="M6 3.5h12v17l-3-2-3 2-3-2-3 2v-17Z"/><path d="M9 8h6M9 12h6"/>',
  settings:
    '<circle cx="12" cy="12" r="3"/><path d="M19 13.7v-3.4l-2-.7-.8-1.8.9-1.9-2.4-2.4-1.9.9-1.8-.8-.7-2H8.3l-.7 2-1.8.8-1.9-.9-2.4 2.4.9 1.9-.8 1.8-2 .7v3.4l2 .7.8 1.8-.9 1.9 2.4 2.4 1.9-.9 1.8.8.7 2h3.4l.7-2 1.8-.8 1.9.9 2.4-2.4-.9-1.9.8-1.8 2-.7Z"/>',
  onboarding: '<path d="M12 3v18M3 12h18"/><circle cx="12" cy="12" r="8.5"/>',
  chevron: '<path d="m9 6 6 6-6 6"/>',
  check: '<path d="m5 12 4.2 4.2L19 6.5"/>',
  arrow: '<path d="M5 12h14M14 7l5 5-5 5"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
};

export function icon(name: keyof typeof paths): string {
  return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name]}</svg>`;
}
