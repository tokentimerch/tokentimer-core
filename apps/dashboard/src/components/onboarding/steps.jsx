import { useState } from 'react';
import { FiArrowLeft, FiList } from 'react-icons/fi';
import { useSearchParams } from 'react-router';
import {
  Box,
  HStack,
  Radio,
  RadioGroup,
  Stack,
  Text,
  VStack,
} from '@chakra-ui/react';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { availableGoals } from './journeyPlanner.js';
import { GOAL_AREAS } from './modules.js';
import {
  isCandidatePick,
  pickHint,
  untestedPlatformsNote,
} from './guidedSetupStatus.js';
import { infrastructuresFor } from './certopsMatrix.js';
import {
  CANDIDATE_NOTE_ID,
  CandidateBadge,
  CandidateNote,
} from './candidateMarks.jsx';
import { progressForGoalChange } from './sessionTransitions.js';

// returnTo is set only when this screen is opened from the steps list while
// another step is in progress: { title, go }.
export function GoalStep({ ctx, returnTo = null }) {
  const { muted } = useDashboardTheme();
  const goals = availableGoals(ctx.capabilities);
  // A link such as /onboarding?area=certops opens straight on one area.
  const [params, setParams] = useSearchParams();
  const requestedArea = params.get('area');
  const areaFilter = GOAL_AREAS.some(a => a.id === requestedArea)
    ? requestedArea
    : '';
  const areas = areaFilter
    ? GOAL_AREAS.filter(a => a.id === areaFilter)
    : GOAL_AREAS;
  const anyCandidate = areas.some(area =>
    goals.some(g => g.area === area.id && isCandidatePick(g.id))
  );
  const current = ctx.session.intent?.goal || '';
  const [choice, setChoice] = useState(current);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      await ctx.controller.update(session => {
        const changed = (session.intent?.goal || '') !== choice;
        return {
          intent: {
            ...session.intent,
            goal: choice,
            // A provider or objective belongs to the previous goal.
            ...(changed ? { provider: '' } : {}),
          },
          // Keep what was imported or created; only reset flags that were
          // about the old goal's steps.
          progress: changed
            ? progressForGoalChange(session.progress, choice)
            : { ...session.progress, verified: false },
          plannerVersion: ctx.plannerVersion,
        };
      });
      await ctx.refresh();
      ctx.onDone?.();
    } catch (e) {
      setError(e.message || 'Could not save your choice.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <StepFrame
      kind='ui'
      title='What do you want to do first?'
      description='Pick one. You can come back for the others, and nothing is created until you confirm a step.'
      docs={ctx.docs('quickstart.firstAsset', 'First asset guide')}
      actions={
        <>
          {returnTo ? (
            <DashboardActionButton
              variant='outline'
              leftIcon={<FiArrowLeft />}
              title={returnTo.title}
              onClick={returnTo.go}
            >
              Back to where I was
            </DashboardActionButton>
          ) : null}
          <PrimaryButton onClick={save} isLoading={saving} isDisabled={!choice}>
            Continue
          </PrimaryButton>
        </>
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {anyCandidate ? <CandidateNote /> : null}
        <RadioGroup value={choice} onChange={setChoice}>
          <VStack align='stretch' spacing={4}>
            {areas.map(area => {
              const inArea = goals.filter(g => g.area === area.id);
              if (inArea.length === 0) return null;
              return (
                <Box key={area.id} role='group' aria-label={area.label}>
                  <Text fontSize='xs' fontWeight='bold' color={muted} mb={2}>
                    {area.label.toUpperCase()}
                  </Text>
                  <Stack spacing={3}>
                    {inArea.map(goal => {
                      const candidate = isCandidatePick(goal.id);
                      const hint = pickHint(goal.id);
                      const scope = candidate
                        ? untestedPlatformsNote(
                            goal.id,
                            goal.certopsObjective
                              ? infrastructuresFor(goal.certopsObjective)
                              : []
                          )
                        : '';
                      const badgeId = `goal-${goal.id}-badge`;
                      const hintId = `goal-${goal.id}-hint`;
                      const scopeId = `goal-${goal.id}-scope`;
                      // Screen readers hear the badge and any extra context.
                      const describedBy = [
                        `goal-${goal.id}-desc`,
                        `goal-${goal.id}-meta`,
                        candidate ? badgeId : '',
                        candidate ? CANDIDATE_NOTE_ID : '',
                        scope ? scopeId : '',
                        candidate && hint ? hintId : '',
                      ]
                        .filter(Boolean)
                        .join(' ');
                      return (
                        <Box key={goal.id}>
                          <HStack>
                            <Radio
                              value={goal.id}
                              isDisabled={Boolean(goal.blocker)}
                              aria-describedby={describedBy}
                            >
                              <Text fontWeight='semibold' fontSize='sm'>
                                {goal.label}
                              </Text>
                            </Radio>
                            {candidate ? <CandidateBadge id={badgeId} /> : null}
                          </HStack>
                          <Text
                            id={`goal-${goal.id}-desc`}
                            fontSize='xs'
                            color={muted}
                            ml={6}
                          >
                            {goal.blocker?.remediation || goal.description}
                          </Text>
                          <Text
                            id={`goal-${goal.id}-meta`}
                            fontSize='xs'
                            color={muted}
                            ml={6}
                          >
                            {[
                              goal.needs ? `Requires: ${goal.needs}` : '',
                              goal.time,
                            ]
                              .filter(Boolean)
                              .join(' ')}
                          </Text>
                          {scope ? (
                            <Text
                              id={scopeId}
                              fontSize='xs'
                              fontWeight='semibold'
                              color={muted}
                              ml={6}
                            >
                              {scope}
                            </Text>
                          ) : null}
                          {candidate && hint ? (
                            <Text
                              id={hintId}
                              fontSize='xs'
                              color={muted}
                              ml={6}
                              mt={1}
                            >
                              {hint}
                            </Text>
                          ) : null}
                        </Box>
                      );
                    })}
                  </Stack>
                </Box>
              );
            })}
          </VStack>
        </RadioGroup>
        {areaFilter ? (
          <Box>
            <DashboardActionButton
              variant='outline'
              size='sm'
              leftIcon={<FiList />}
              onClick={() => setParams({}, { replace: true })}
            >
              Show all goals
            </DashboardActionButton>
          </Box>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
export { MonitorStep } from './monitorStep.jsx';
export { AssetStep } from './assetStep.jsx';
