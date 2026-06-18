// État React persisté dans localStorage (préférences UI conservées entre
// sessions). Sérialisation JSON, tolérante : un stockage indisponible ou une
// valeur corrompue retombe sur la valeur initiale sans casser le rendu.

import { useEffect, useState } from "react";

export function usePersistentState<T>(key: string, initial: T): [T, (value: T) => void] {
  const [value, setValue] = useState<T>(() => read(key, initial));

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // stockage indisponible (mode privé, quota) : préférence non persistée.
    }
  }, [key, value]);

  return [value, setValue];
}

function read<T>(key: string, initial: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? initial : (JSON.parse(raw) as T);
  } catch {
    return initial;
  }
}
