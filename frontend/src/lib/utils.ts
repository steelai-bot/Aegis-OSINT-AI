import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// XSS Prevention: Escape HTML in user-controlled data
export function escapeHtml(str: unknown): string {
  if (str === null || str === undefined) return ''
  const div = document.createElement('div')
  div.appendChild(document.createTextNode(String(str)))
  return div.innerHTML
}