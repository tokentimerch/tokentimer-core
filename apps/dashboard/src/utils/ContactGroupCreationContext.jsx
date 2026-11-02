import {
  createContext,
  lazy,
  Suspense,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import { Text } from '@chakra-ui/react';
import { WorkspaceProvider, useWorkspace } from './WorkspaceContext.jsx';
import { workspaceAPI } from './apiClient';

const AlertPreferences = lazy(() => import('../pages/AlertPreferences.jsx'));
const Context = createContext(null);
export const useContactGroupCreation = () => useContext(Context);

export function ContactGroupWorkspaceProvider({ children, ...props }) {
  return (
    <WorkspaceProvider {...props}>
      <ContactGroupCreationProvider>{children}</ContactGroupCreationProvider>
    </WorkspaceProvider>
  );
}

/** Open the existing preferences editor without navigating or unmounting a form. */
export function ContactGroupCreationProvider({ children }) {
  const { workspaceId } = useWorkspace();
  const [permission, setPermission] = useState(null);
  const [created, setCreated] = useState({ workspaceId, groups: [] });
  const [request, setRequest] = useState(null);
  const activeWorkspace = useRef(workspaceId);
  const finalFocusRef = useRef(null);
  const focusReturnPending = useRef(false);
  activeWorkspace.current = workspaceId;

  useEffect(() => {
    let live = true;
    setPermission(null);
    setRequest(null);
    if (workspaceId)
      workspaceAPI
        .get(workspaceId)
        .then(workspace => {
          if (live)
            setPermission({
              workspaceId,
              allowed: ['admin', 'workspace_manager'].includes(workspace.role),
            });
        })
        .catch(() => {});
    return () => {
      live = false;
    };
  }, [workspaceId]);

  useEffect(() => {
    if (request || !focusReturnPending.current || !finalFocusRef.current)
      return undefined;
    focusReturnPending.current = false;
    const trigger = finalFocusRef.current;
    // The parent form's focus trap reactivates when the editor unmounts.
    // Restore its picker after that commit, once the browser reaches a frame.
    const frame = requestAnimationFrame(() => {
      if (trigger.isConnected) trigger.focus();
      if (finalFocusRef.current === trigger) finalFocusRef.current = null;
    });
    return () => cancelAnimationFrame(frame);
  }, [request, workspaceId]);

  const open = (onCreated, trigger, ownerId) => {
    if (permission?.workspaceId !== workspaceId || !permission.allowed) return;
    focusReturnPending.current = false;
    finalFocusRef.current = trigger;
    setRequest({ workspaceId, onCreated, ownerId });
  };
  const saved = group => {
    if (request?.workspaceId !== activeWorkspace.current) return;
    setCreated(previous => ({
      workspaceId,
      groups: [
        ...(previous.workspaceId === workspaceId ? previous.groups : []),
        group,
      ],
    }));
    request.onCreated(group);
  };

  return (
    <Context.Provider
      value={{
        canCreate:
          permission?.workspaceId === workspaceId && permission.allowed,
        groups: created.workspaceId === workspaceId ? created.groups : [],
        open,
        // Keep the dialog in the initiating form's React tree. Chakra's first
        // modal owns the scroll lock, so a sibling portal would be treated as
        // outside that lock and have all wheel/touch scrolling cancelled.
        renderEditor: ownerId =>
          request?.ownerId === ownerId ? (
            <Suspense
              fallback={
                <Text role='status'>Loading contact group editor…</Text>
              }
            >
              <AlertPreferences
                key={request.workspaceId}
                groupCreationOnly
                onGroupCreated={saved}
                onGroupCreationClosed={() => {
                  focusReturnPending.current =
                    request.workspaceId === activeWorkspace.current;
                  setRequest(null);
                }}
                groupFinalFocusRef={finalFocusRef}
              />
            </Suspense>
          ) : null,
      }}
    >
      {children}
    </Context.Provider>
  );
}
