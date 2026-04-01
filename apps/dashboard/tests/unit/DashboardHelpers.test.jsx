import React from 'react';
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import {
  domainStatusColor,
  domainFormatUrl,
  domainSslBadge,
} from '../../src/components/DashboardHelpers.jsx';

describe('DashboardHelpers', () => {
  it('maps endpoint status to color', () => {
    expect(domainStatusColor('healthy')).toBe('green');
    expect(domainStatusColor('unhealthy')).toBe('orange');
    expect(domainStatusColor('error')).toBe('red');
    expect(domainStatusColor('unknown')).toBe('gray');
  });

  it('formats URL host/path and falls back for invalid URL', () => {
    expect(domainFormatUrl('https://api.example.com/health')).toBe(
      'api.example.com/health'
    );
    expect(domainFormatUrl('https://api.example.com/')).toBe('api.example.com');
    expect(domainFormatUrl('not-a-url')).toBe('not-a-url');
  });

  it('renders SSL badges for no cert, expired, warning, and valid', () => {
    const noCert = render(domainSslBadge({ ssl_valid_to: null }));
    expect(noCert.getByText('No SSL')).toBeInTheDocument();
    noCert.unmount();

    const expired = render(
      domainSslBadge({
        ssl_valid_to: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
      })
    );
    expect(expired.getByText('Expired')).toBeInTheDocument();
    expired.unmount();

    const warning = render(
      domainSslBadge({
        ssl_valid_to: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
      })
    );
    expect(warning.getByText(/d left/)).toBeInTheDocument();
    warning.unmount();

    const valid = render(
      domainSslBadge({
        ssl_valid_to: new Date(
          Date.now() + 45 * 24 * 3600 * 1000
        ).toISOString(),
      })
    );
    expect(valid.getByText(/Valid/)).toBeInTheDocument();
    valid.unmount();
  });
});
