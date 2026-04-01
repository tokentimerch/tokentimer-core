import { Helmet } from 'react-helmet-async';

/**
 * Minimal SEO component for the self-hosted core product.
 * Only sets the page <title>. All OpenGraph, Twitter, canonical,
 * JSON-LD, and hreflang props are accepted but ignored.
 */
export default function SEO({ title }) {
  const siteName = 'TokenTimer';
  const fullTitle = title ? `${title} | ${siteName}` : siteName;

  return (
    <Helmet>
      {fullTitle && <title>{fullTitle}</title>}
      <meta name='robots' content='noindex, nofollow' />
    </Helmet>
  );
}
