import { Box, Image, Tooltip } from '@chakra-ui/react';
import { FiKey, FiUsers } from 'react-icons/fi';

/**
 * Logo files for the import sources. The import dialog and the setup guide
 * both read this, so a provider looks the same in both.
 */
export const IMPORT_SOURCE_LOGOS = {
  vault: '/Branding/vendor-logos/hashicorp.png',
  gitlab: '/Branding/vendor-logos/gitlab.png',
  github: '/Branding/vendor-logos/github.png',
  aws: '/Branding/vendor-logos/aws.png',
  azure: '/Branding/vendor-logos/azure.svg',
  'azure-ad': '/Branding/vendor-logos/azure.svg',
  gcp: '/Branding/vendor-logos/google-cloud-icon.png',
};

// Both Azure sources share one logo, so a small badge tells them apart.
const AZURE_BADGES = {
  azure: { icon: FiKey, bg: 'blue.500', label: 'Azure Key Vault' },
  'azure-ad': {
    icon: FiUsers,
    bg: 'purple.500',
    label: 'Azure Active Directory',
  },
};

/**
 * The logo of one import source. Decorative: the control that wraps it names
 * the provider, so assistive tech should not read the image as well.
 */
export function ImportSourceLogo({
  sourceKey,
  maxH = { base: '56px', md: '72px' },
  dimmed = false,
}) {
  const src = IMPORT_SOURCE_LOGOS[sourceKey];
  if (!src) return null;
  const badge = AZURE_BADGES[sourceKey];
  return (
    <Box position='relative'>
      <Image
        src={src}
        alt=''
        aria-hidden
        maxH={maxH}
        maxW='100%'
        objectFit='contain'
        opacity={dimmed ? 0.4 : 1}
        filter={dimmed ? 'grayscale(100%)' : 'none'}
      />
      {badge ? (
        <Tooltip label={badge.label} fontSize='xs'>
          <Box
            position='absolute'
            top='-6px'
            right='-6px'
            bg={badge.bg}
            borderRadius='full'
            p={1.5}
            boxShadow='md'
            border='2px solid white'
          >
            <Box as={badge.icon} boxSize='14px' color='white' />
          </Box>
        </Tooltip>
      ) : null}
    </Box>
  );
}
