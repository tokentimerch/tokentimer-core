import { createContext } from 'react';

// True when the import dialog is opened from the setup guide.
export const EmbeddedImportContext = createContext(false);

export const EMBEDDED_GROUPS_NOTE =
  'Groups chosen here receive alerts for the assets you import now. Assets a sync adds later use the group set on the sync.';
