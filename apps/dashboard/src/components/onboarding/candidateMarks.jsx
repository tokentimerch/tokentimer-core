import { Alert, AlertDescription, AlertIcon, Badge } from '@chakra-ui/react';
import { INFO_NOTE_PROPS } from '../LearnMorePanel';
import {
  CANDIDATE_BADGE,
  CANDIDATE_EXPLANATION,
  CANDIDATE_NOTE,
} from './guidedSetupStatus.js';

export const CANDIDATE_NOTE_ID = 'candidate-note';

/** One shared sentence above a list of picks, shown only if one is marked. */
export function CandidateNote() {
  return (
    <Alert {...INFO_NOTE_PROPS}>
      <AlertIcon />
      <AlertDescription id={CANDIDATE_NOTE_ID} fontSize='xs' lineHeight='1.45'>
        {CANDIDATE_NOTE}
      </AlertDescription>
    </Alert>
  );
}

/** The badge carries an id so a radio can include it in its description. */
export function CandidateBadge({ id }) {
  return (
    <Badge id={id} colorScheme='orange' title={CANDIDATE_EXPLANATION}>
      {CANDIDATE_BADGE}
    </Badge>
  );
}
