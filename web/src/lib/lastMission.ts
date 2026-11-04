/**
 * The mission the operator last opened. The mission sidebar is also shown on
 * the pages that live outside a mission (Help, administration), so those need
 * to know which mission to point back at.
 */
const KEY = 'nety.last-mission'

export function rememberMission(id: number): void {
  if (!Number.isFinite(id) || id <= 0) return
  try {
    localStorage.setItem(KEY, String(id))
  } catch {
    /* storage can be blocked; the sidebar simply shows no mission section */
  }
}

export function lastMissionId(): number | null {
  try {
    const v = Number(localStorage.getItem(KEY))
    return Number.isFinite(v) && v > 0 ? v : null
  } catch {
    return null
  }
}
