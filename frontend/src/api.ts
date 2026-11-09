import { requestJson } from './request'

const base = (import.meta.env.VITE_API_BASE as string | undefined)?.replace(/\/$/, '') ?? ''

export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  return requestJson<T>(`${base}/api${path}`, options)
}

export function num(value: number | undefined): string { return new Intl.NumberFormat('en-US').format(value ?? 0) }
export function compact(value: number | undefined): string { return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value ?? 0) }
export function bytes(value: number | undefined): string {
  if (!value) return '0 B'
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4)
  return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${['B', 'KB', 'MB', 'GB', 'TB'][index]}`
}
export function date(value: string | undefined): string { return value ? new Date(value).toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—' }
export function time(value: string | undefined): string { return value ? new Date(value).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '—' }
export function percentage(value: number | undefined): string { return `${((value ?? 0) * 100).toFixed(1)}%` }


