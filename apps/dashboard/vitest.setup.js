import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';

vi.mock('./src/utils/contactGroupPluralWrites.jsx', () => ({
  useContactGroupPluralWrites: () => true,
  ContactGroupPluralWritesProvider: ({ children }) => children,
}));
