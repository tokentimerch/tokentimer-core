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
    label: 'Microsoft Entra ID',
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
    // The badge sits in the wrapper's own padding, so a parent that clips at
    // the wrapper edge cannot cut it off. Same place on screen as before.
    <Box
      position='relative'
      display='inline-flex'
      p={badge ? '6px' : undefined}
      overflow='visible'
      data-testid='import-source-logo'
    >
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
            top='0'
            right='0'
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

// Which sources the import dialog shows. Not related to the logo artwork.
export function isSourceVisible(key, { sourceChoices, hiddenSources } = {}) {
  if (Array.isArray(sourceChoices) && !sourceChoices.includes(key))
    return false;
  if (Array.isArray(hiddenSources) && hiddenSources.includes(key)) return false;
  return true;
}

/** The source the dialog starts on: the asked one if visible, else File, else the first visible. */
export function resolveStartSource(
  { initialSource, sourceChoices, hiddenSources } = {},
  allKeys = ['file', ...Object.keys(IMPORT_SOURCE_LOGOS), 'cert-pem']
) {
  const visible = allKeys.filter(k =>
    isSourceVisible(k, { sourceChoices, hiddenSources })
  );
  if (initialSource && visible.includes(initialSource)) return initialSource;
  return visible.includes('file') ? 'file' : visible[0] || 'file';
}
