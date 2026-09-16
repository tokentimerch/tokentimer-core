import { createContext, useContext } from 'react';

// Match API default: CONTACT_GROUP_PLURAL_WRITES unset = on.
const ContactGroupPluralWritesContext = createContext(true);

export function ContactGroupPluralWritesProvider({ value, children }) {
  return (
    <ContactGroupPluralWritesContext.Provider value={value !== false}>
      {children}
    </ContactGroupPluralWritesContext.Provider>
  );
}

export function useContactGroupPluralWrites() {
  return useContext(ContactGroupPluralWritesContext);
}
