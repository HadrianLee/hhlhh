import { useCallback, useEffect, useState } from 'react'
import { get, message } from './api'

export function useResource<T>(path: string) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const reload = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setError('')
    try {
      const result = await get<T>(path, signal)
      if (!signal?.aborted) setData(result)
      return result
    } catch (caught) {
      if (!signal?.aborted) setError(message(caught))
      throw caught
    } finally { if (!signal?.aborted) setLoading(false) }
  }, [path])
  useEffect(() => {
    const controller = new AbortController()
    setData(null)
    void reload(controller.signal).catch(() => {})
    return () => controller.abort()
  }, [reload])
  return { data, error, loading, reload }
}
