import { Link as RouterLink } from 'react-router';
import { Button, VStack } from '@chakra-ui/react';
import { FiArrowLeft } from 'react-icons/fi';
import SEO from './SEO.jsx';
import DashboardPageLayout from './DashboardPageLayout';
import { DashboardPanelHeader } from './DashboardPrimitives';
import { SETTINGS_SECTION_GAP } from '../styles/dashboardLayout';

/**
 * Shared chrome for SSO admin pages on the v0.8.0 dashboard shell.
 */
export default function SsoAdminPageShell({
  seoTitle,
  title,
  subtitle,
  actions,
  variant = 'form',
  children,
  session,
  onLogout,
  onAccountClick,
}) {
  return (
    <>
      <SEO title={seoTitle || title} />
      <DashboardPageLayout
        session={session}
        onLogout={onLogout}
        onAccountClick={onAccountClick}
        pageTitle={title}
        variant={variant}
        contentProps={{ overflowX: 'hidden', w: 'full', maxW: '100%' }}
      >
        <VStack align='stretch' spacing={SETTINGS_SECTION_GAP} w='full'>
          <Button
            as={RouterLink}
            to='/system-settings'
            size='sm'
            variant='ghost'
            leftIcon={<FiArrowLeft />}
            alignSelf='flex-start'
            px={0}
            _hover={{ bg: 'transparent', textDecoration: 'underline' }}
          >
            System Settings
          </Button>
          <DashboardPanelHeader
            title={title}
            description={subtitle}
            action={actions}
          />
          {children}
        </VStack>
      </DashboardPageLayout>
    </>
  );
}
