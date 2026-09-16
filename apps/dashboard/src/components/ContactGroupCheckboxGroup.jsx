import SelectMenu from './SelectMenu.jsx';
import { useContactGroupPluralWrites } from '../utils/contactGroupPluralWrites.jsx';

/**
 * Contact-group picker. Empty selection means workspace default.
 * Multi-select when plural writes are enabled (or allowMultiple=true).
 */
export default function ContactGroupCheckboxGroup({
  contactGroups = [],
  value = [],
  onChange,
  isDisabled = false,
  emptyText = 'No contact groups in this workspace.',
  helperText = 'Leave empty to use the workspace default.',
  defaultContactGroupId = '',
  size = 'sm',
  maxH = '240px',
  allowMultiple,
}) {
  const pluralWritesEnabled = useContactGroupPluralWrites();
  const canSelectMultiple =
    allowMultiple === undefined ? pluralWritesEnabled : allowMultiple === true;
  const groups = Array.isArray(contactGroups) ? contactGroups : [];
  const options = groups.map(group => {
    const id = String(group.id);
    const isDefault =
      defaultContactGroupId && id === String(defaultContactGroupId);
    return {
      value: id,
      label: `${group.name}${isDefault ? ' (workspace default group)' : ''}`,
    };
  });

  return (
    <SelectMenu
      options={options}
      value={value}
      onChange={onChange}
      multiple={canSelectMultiple}
      isDisabled={isDisabled}
      emptyText={emptyText}
      helperText={
        canSelectMultiple
          ? helperText
          : 'Select one contact group, or leave as workspace default.'
      }
      // Multi: clear by deselecting items (placeholder already means default).
      // Single: explicit "Workspace default" radio clears the selection.
      allowEmpty={!canSelectMultiple}
      emptyOptionLabel='Workspace default'
      placeholder='Workspace default'
      size={size}
      maxMenuH={maxH}
      aria-label='Contact groups'
    />
  );
}
