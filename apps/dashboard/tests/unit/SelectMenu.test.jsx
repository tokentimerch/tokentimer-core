import { fireEvent, render, screen } from '@testing-library/react';
import React from 'react';
import {
  ChakraProvider,
  Modal,
  ModalBody,
  ModalContent,
  ModalOverlay,
} from '@chakra-ui/react';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import SelectMenu from '../../src/components/SelectMenu.jsx';
import ContactGroupCheckboxGroup from '../../src/components/ContactGroupCheckboxGroup.jsx';
import { ContactGroupPluralWritesProvider } from '../../src/utils/contactGroupPluralWrites.jsx';

beforeAll(() => {
  // jsdom lacks Element.scrollTo; Chakra Menu calls it on open.
  Element.prototype.scrollTo = function scrollTo() {};
});

function renderMenu(props) {
  return render(
    <ChakraProvider>
      <SelectMenu
        options={[
          { value: 'a', label: 'Alpha' },
          { value: 'b', label: 'Beta' },
          { value: 'c', label: 'Gamma' },
        ]}
        value={[]}
        onChange={vi.fn()}
        {...props}
      />
    </ChakraProvider>
  );
}

describe('SelectMenu', () => {
  it('selects a single option from the dropdown', () => {
    const onChange = vi.fn();
    renderMenu({ multiple: false, onChange, placeholder: 'Pick one' });

    fireEvent.click(screen.getByRole('button', { name: 'Pick one' }));
    fireEvent.pointerDown(screen.getByText('Alpha'));
    expect(onChange).toHaveBeenLastCalledWith(['a']);
  });

  it('selects a group from an empty workspace-default state in multi mode', () => {
    const onChange = vi.fn();
    renderMenu({
      multiple: true,
      allowEmpty: true,
      emptyOptionLabel: 'Workspace default',
      onChange,
      value: [],
      placeholder: 'Workspace default',
    });

    fireEvent.click(
      screen.getByRole('button', { name: 'Workspace default' })
    );
    fireEvent.pointerDown(screen.getByText('Alpha'));
    expect(onChange).toHaveBeenLastCalledWith(['a']);
  });

  it('selects a contact group from inside an open modal', () => {
    const onChange = vi.fn();
    render(
      <ChakraProvider>
        <ContactGroupPluralWritesProvider value={true}>
          <Modal isOpen onClose={() => {}}>
            <ModalOverlay />
            <ModalContent>
              <ModalBody>
                <ContactGroupCheckboxGroup
                  contactGroups={[
                    { id: 1, name: 'Ops' },
                    { id: 2, name: 'Security' },
                  ]}
                  value={[]}
                  onChange={onChange}
                  defaultContactGroupId='1'
                />
              </ModalBody>
            </ModalContent>
          </Modal>
        </ContactGroupPluralWritesProvider>
      </ChakraProvider>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Contact groups' }));
    fireEvent.pointerDown(
      screen.getByText('Ops (workspace default group)')
    );
    expect(onChange).toHaveBeenLastCalledWith(['1']);
  });

  it('allows multiple selections when multiple is true', () => {
    const onChange = vi.fn();
    function Harness() {
      const [value, setValue] = React.useState([]);
      return (
        <SelectMenu
          options={[
            { value: 'a', label: 'Alpha' },
            { value: 'b', label: 'Beta' },
            { value: 'c', label: 'Gamma' },
          ]}
          multiple
          value={value}
          onChange={next => {
            onChange(next);
            setValue(next);
          }}
          placeholder='Pick many'
        />
      );
    }
    render(
      <ChakraProvider>
        <Harness />
      </ChakraProvider>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Pick many' }));
    fireEvent.pointerDown(screen.getByText('Alpha'));
    expect(onChange).toHaveBeenLastCalledWith(['a']);

    fireEvent.pointerDown(screen.getByText('Beta'));
    expect(onChange).toHaveBeenLastCalledWith(['a', 'b']);
  });

  it('clears selection via the empty option in single mode', () => {
    const onChange = vi.fn();
    renderMenu({
      multiple: false,
      onChange,
      value: ['b'],
      placeholder: 'Pick one',
      emptyOptionLabel: 'Workspace default',
    });

    fireEvent.click(screen.getByRole('button', { name: 'Pick one' }));
    fireEvent.pointerDown(screen.getByText('Workspace default'));
    expect(onChange).toHaveBeenLastCalledWith([]);
  });

  it('renders a summary for multiple selected values', () => {
    renderMenu({
      multiple: true,
      value: ['a', 'b', 'c'],
      placeholder: 'Pick many',
    });
    expect(screen.getByRole('button', { name: 'Pick many' })).toHaveTextContent(
      '3 selected'
    );
  });

  it('shows emptyText when there are no options', () => {
    render(
      <ChakraProvider>
        <SelectMenu options={[]} emptyText='Nothing here' />
      </ChakraProvider>
    );
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
  });
});
