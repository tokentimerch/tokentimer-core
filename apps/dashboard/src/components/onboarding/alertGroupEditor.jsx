import { lazy, Suspense, useState } from 'react';
import { Spinner } from '@chakra-ui/react';
import PrimaryButton from './PrimaryButton.jsx';

const AlertPreferences = lazy(() => import('../../pages/AlertPreferences.jsx'));

/** Use the same contact-group and contact dialogs as every group picker. */
export default function GroupEditor({
  ctx,
  group,
  makeDefault,
  onSaved,
  onCancel,
  autoOpen = false,
}) {
  const [open, setOpen] = useState(Boolean(group) || autoOpen);
  const [saved, setSaved] = useState(false);
  return (
    <>
      <PrimaryButton
        onClick={() => {
          setSaved(false);
          setOpen(true);
        }}
      >
        {group ? 'Edit group' : 'Create a new group'}
      </PrimaryButton>
      {open && (
        <Suspense fallback={<Spinner size='sm' />}>
          <AlertPreferences
            groupCreationOnly
            initialGroup={group}
            suggestDefaultGroup={makeDefault}
            onGroupSaved={async created => {
              await ctx.controller.update(session => ({
                operation_refs: {
                  ...session.operationRefs,
                  contactGroupId: created.id,
                },
              }));
              setSaved(true);
            }}
            onGroupCreationClosed={async () => {
              setOpen(false);
              if (saved) await onSaved();
              else onCancel?.();
            }}
          />
        </Suspense>
      )}
    </>
  );
}
