import { createContext, useContext } from 'react';

const ContactGroupPluralWritesContext = createContext(false);

export function ContactGroupPluralWritesProvider({ value, children }) {
  return (
    <ContactGroupPluralWritesContext.Provider value={value === true}>
      {children}
    </ContactGroupPluralWritesContext.Provider>
  );
}

export function useContactGroupPluralWrites() {
  return useContext(ContactGroupPluralWritesContext);
}
