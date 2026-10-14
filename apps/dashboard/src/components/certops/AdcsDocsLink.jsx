import { Link } from '@chakra-ui/react';
import { FiExternalLink } from 'react-icons/fi';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme.js';

/** Doc anchor, kept out of FormHelperText so it does not inherit the muted color. */
export default function AdcsDocsLink({ href, children }) {
  const { dashboard } = useDashboardThemeColors();
  return (
    <Link
      href={href}
      isExternal
      display='inline-flex'
      alignItems='center'
      gap='1.5'
      mt={1}
      fontSize='sm'
      fontWeight='semibold'
      color={dashboard.accent.interactiveForeground}
      textDecoration='underline'
      textUnderlineOffset='3px'
    >
      {children}
      <FiExternalLink aria-hidden='true' />
    </Link>
  );
}
