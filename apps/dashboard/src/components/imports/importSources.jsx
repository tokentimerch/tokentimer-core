import { Box, Image } from '@chakra-ui/react';

/**
 * Logo files for the import sources. The import dialog and the setup guide
 * both read this, so a provider looks the same in both. Azure Key Vault and
 * Microsoft Entra ID have their own glyph instead of sharing the Azure mark
 * with a badge, which clipped and doubled the background.
 */
export const IMPORT_SOURCE_LOGOS = {
  vault: '/Branding/vendor-logos/hashicorp.png',
  gitlab: '/Branding/vendor-logos/gitlab.png',
  github: '/Branding/vendor-logos/github.png',
  aws: '/Branding/vendor-logos/aws.png',
  azure: '/Branding/vendor-logos/azure-key-vault.svg',
  'azure-ad': '/Branding/vendor-logos/entra-id.svg',
  gcp: '/Branding/vendor-logos/google-cloud-icon.png',
};

/** Readable names, used as the accessible name of a tile. */
export const IMPORT_SOURCE_NAMES = {
  vault: 'HashiCorp Vault',
  gitlab: 'GitLab',
  github: 'GitHub',
  aws: 'AWS',
  azure: 'Azure Key Vault',
  'azure-ad': 'Microsoft Entra ID',
  gcp: 'Google Cloud',
};

/** Sources that are not integrations. */
export const NON_INTEGRATION_SOURCES = ['file', 'cert-pem'];

/**
 * Whether the dialog shows a source. `sourceChoices` is an allow list,
 * `hiddenSources` a deny list; both unset shows everything.
 */
export function isSourceVisible(key, { sourceChoices, hiddenSources } = {}) {
  if (Array.isArray(sourceChoices) && !sourceChoices.includes(key))
    return false;
  if (Array.isArray(hiddenSources) && hiddenSources.includes(key)) return false;
  return true;
}

/** The source the dialog starts on: the asked one if visible, else the first visible. */
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
  return (
    <Box position='relative' display='flex' alignItems='center'>
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
    </Box>
  );
}
