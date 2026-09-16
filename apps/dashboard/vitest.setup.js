import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';

// jsdom does not implement these; Chakra and alert deep-links call them.
Element.prototype.scrollIntoView = function scrollIntoView() {};
Element.prototype.scrollTo = function scrollTo() {};

vi.mock('./src/utils/contactGroupPluralWrites.jsx', () => ({
  useContactGroupPluralWrites: () => true,
  ContactGroupPluralWritesProvider: ({ children }) => children,
}));
