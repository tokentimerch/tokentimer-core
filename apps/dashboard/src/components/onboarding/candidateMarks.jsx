import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Link,
} from '@chakra-ui/react';
import { INFO_NOTE_PROPS } from '../LearnMorePanel';
import {
  CANDIDATE_BADGE,
  CANDIDATE_EXPLANATION,
  CANDIDATE_NOTE,
  CANDIDATE_REPORT_LABEL,
  CANDIDATE_REPORT_URL,
} from './guidedSetupStatus.js';

export const CANDIDATE_NOTE_ID = 'candidate-note';

/** One shared sentence above a list of picks, shown only if one is marked. */
export function CandidateNote() {
  return (
    <Alert {...INFO_NOTE_PROPS}>
      <AlertIcon />
      <AlertDescription id={CANDIDATE_NOTE_ID} fontSize='xs' lineHeight='1.45'>
        {CANDIDATE_NOTE}{' '}
        <Link
          href={CANDIDATE_REPORT_URL}
          isExternal
          textDecoration='underline'
          fontWeight='semibold'
        >
          {CANDIDATE_REPORT_LABEL}
        </Link>
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
