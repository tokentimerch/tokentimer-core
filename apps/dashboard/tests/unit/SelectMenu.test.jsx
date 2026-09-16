import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import SelectMenu from '../../src/components/SelectMenu.jsx';

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
    fireEvent.click(screen.getByText('Alpha'));
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
    fireEvent.click(screen.getByText('Alpha'));
    expect(onChange).toHaveBeenLastCalledWith(['a']);
  });

  it('allows multiple selections when multiple is true', () => {
    const onChange = vi.fn();
    const { rerender } = renderMenu({
      multiple: true,
      onChange,
      value: [],
      placeholder: 'Pick many',
    });

    fireEvent.click(screen.getByRole('button', { name: 'Pick many' }));
    fireEvent.click(screen.getByText('Alpha'));
    expect(onChange).toHaveBeenLastCalledWith(['a']);

    rerender(
      <ChakraProvider>
        <SelectMenu
          options={[
            { value: 'a', label: 'Alpha' },
            { value: 'b', label: 'Beta' },
            { value: 'c', label: 'Gamma' },
          ]}
          multiple
          value={['a']}
          onChange={onChange}
          placeholder='Pick many'
        />
      </ChakraProvider>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Pick many' }));
    fireEvent.click(screen.getByText('Beta'));
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
    fireEvent.click(screen.getByText('Workspace default'));
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
