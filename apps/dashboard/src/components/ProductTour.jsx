import { useEffect, useMemo, useState, useCallback, useRef } from 'react';
import Joyride, { ACTIONS, EVENTS, STATUS } from 'react-joyride';
import {
  useColorMode,
  useColorModeValue,
  useToken,
  Button,
  HStack,
  Box,
} from '@chakra-ui/react';
import { useNavigate } from 'react-router-dom';
import { trackEvent } from '../utils/analytics';
import { logger } from '../utils/logger';

/**
 * Custom Tooltip Component for react-joyride
 * Shows custom buttons on the last step
 */
const CustomTooltip = ({
  continuous: _continuous,
  index,
  step,
  backProps,
  closeProps,
  primaryProps,
  skipProps,
  tooltipProps,
  _size,
  isLastStep,
}) => {
  const navigate = useNavigate();
  const { colorMode: _colorMode } = useColorMode();
  const [brand500, brand400, gray700, gray200, gray800, gray600, white] =
    useToken('colors', [
      'blue.500',
      'blue.400',
      'gray.700',
      'gray.200',
      'gray.800',
      'gray.600',
      'white',
    ]);

  const tooltipBg = useColorModeValue(white, gray800);
  const tooltipBorder = useColorModeValue('rgba(0,0,0,0.08)', gray600);
  const textColor = useColorModeValue(gray700, gray200);
  const buttonBg = useColorModeValue(brand500, brand400);
  const hoverBg = useColorModeValue('gray.50', 'gray.700');

  const handleGetStarted = e => {
    e?.preventDefault?.();
    e?.stopPropagation?.();
    if (closeProps?.onClick) {
      closeProps.onClick(e);
    }
    // Force a reload to clear all tour state and mock data
    window.location.href = '/dashboard';
  };

  const handleSeeDocs = e => {
    e?.preventDefault?.();
    e?.stopPropagation?.();
    if (closeProps?.onClick) {
      closeProps.onClick(e);
    }
    navigate('/docs');
  };

  return (
    <Box
      {...tooltipProps}
      bg={tooltipBg}
      border={`1px solid ${tooltipBorder}`}
      borderRadius={8}
      p={{ base: 3, md: 4 }}
      maxW={{ base: 'calc(100vw - 32px)', sm: '320px', md: 400 }}
      w={{ base: 'calc(100vw - 32px)', sm: 'auto' }}
      boxShadow='lg'
    >
      {step.title && (
        <Box
          as='h4'
          fontSize='lg'
          fontWeight='semibold'
          mb={2}
          color={textColor}
        >
          {step.title}
        </Box>
      )}
      <Box mb={4} color={textColor} fontSize='sm' lineHeight='1.6'>
        {step.content}
      </Box>
      <HStack spacing={2} justify='flex-end'>
        {index > 0 && (
          <Button
            {...backProps}
            variant='ghost'
            size='sm'
            color={textColor}
            fontSize='sm'
          >
            Back
          </Button>
        )}
        {isLastStep ? (
          <>
            <Button
              onClick={handleGetStarted}
              size='sm'
              bg={buttonBg}
              color='white'
              _hover={{ opacity: 0.9 }}
              fontSize='sm'
              fontWeight={500}
            >
              Get started
            </Button>
            <Button
              onClick={handleSeeDocs}
              size='sm'
              variant='outline'
              color={textColor}
              borderColor={tooltipBorder}
              _hover={{ bg: hoverBg }}
              fontSize='sm'
              fontWeight={500}
            >
              See docs
            </Button>
          </>
        ) : (
          <>
            {skipProps && (
              <Button
                {...skipProps}
                variant='ghost'
                size='sm'
                color={textColor}
                fontSize='sm'
              >
                Skip tour
              </Button>
            )}
            <Button
              {...primaryProps}
              size='sm'
              bg={buttonBg}
              color='white'
              _hover={{ opacity: 0.9 }}
              fontSize='sm'
              fontWeight={500}
            >
              {primaryProps?.children || 'Next'}
            </Button>
          </>
        )}
      </HStack>
    </Box>
  );
};

/**
 * Product Tour Component using react-joyride
 * Provides interactive onboarding tours for new users
 */
export default function ProductTour({
  run = false,
  tourType = 'dashboard',
  onTourComplete,
  forceRun = false, // Bypass localStorage check for demos
}) {
  const { colorMode } = useColorMode();
  const navigate = useNavigate();
  const [stepIndex, setStepIndex] = useState(0);
  const [isRunning, setIsRunning] = useState(false);

  // Resolve exact color tokens (hex) for libraries that expect computed values
  const [brand500, brand400, gray700, gray200, gray800, gray600, white] =
    useToken('colors', [
      'blue.500',
      'blue.400',
      'gray.700',
      'gray.200',
      'gray.800',
      'gray.600',
      'white',
    ]);

  // Theme colors that match Chakra UI - properly handle dark/light themes
  const tooltipBg = useColorModeValue(white, gray800);
  const tooltipBorder = useColorModeValue('rgba(0,0,0,0.08)', gray600);
  const primaryColor = useColorModeValue(brand500, 'blue.300');
  const textColor = useColorModeValue(gray700, gray200);
  const buttonBg = useColorModeValue(brand500, brand400);

  // Helper to detect mobile
  const _isMobile = useMemo(() => {
    if (typeof window === 'undefined') return false;
    return window.innerWidth < 768; // md breakpoint
  }, []);

  // Helper to get responsive target (kept for future use, if needed)
  const _getResponsiveTarget = useCallback((desktopTarget, mobileTarget) => {
    if (typeof window === 'undefined') return desktopTarget;
    const isMobileView = window.innerWidth < 768;
    return isMobileView ? mobileTarget : desktopTarget;
  }, []);

  // Steps (memoized)
  const steps = useMemo(() => {
    const dashboardSteps = [
      // Workspace selector - desktop only
      {
        target: '[data-tour="workspace-selector"]',
        content:
          'Select or switch between workspaces here. Workspaces help organize tokens by team or project.',
        placement: 'bottom',
        disableBeacon: true,
        isDesktopOnly: true,
      },
      // Mobile menu button - mobile only
      {
        target: '[data-tour="mobile-menu-button"]',
        content: 'Tap here to open the navigation menu.',
        placement: 'bottom',
        disableBeacon: true,
        isMobileOnly: true,
      },
      // Tokens nav - responsive
      {
        target: '[data-tour="tokens-nav"]',
        content:
          'The Tokens page is the dashboard where you manage all your certificates, API keys, secrets, documents and licenses. (aka "Tokens")',
        placement: 'bottom',
        mobileTarget: '[data-tour="mobile-tokens-nav"]',
        mobilePlacement: 'right', // Drawer is on left
      },
      {
        target: '[data-tour="add-token-form"]',
        content:
          'Create new tokens here. Fill in the name, category, type, and expiration date. You can also add optional details.',
        placement: 'top',
        mobilePlacement: 'bottom', // On mobile, use bottom to avoid going off-screen
      },
      {
        target: '[data-tour="import-tokens"]',
        content:
          'Bulk import from files (CSV, XLSX, JSON, YAML) or use our integrations: GitLab, GitHub, AWS, Azure, HashiCorp Vault, GCP, etc...',
        placement: 'top',
        mobilePlacement: 'bottom', // On mobile, use bottom to avoid going off-screen
      },
      {
        target: '[data-tour="export-tokens"]',
        content:
          'Export your tokens to CSV, XLSX, JSON, or YAML format for backup or migration purposes.',
        placement: 'top',
        mobilePlacement: 'bottom', // On mobile, use bottom to avoid going off-screen
      },
      {
        target: '[data-tour="token-list"]',
        content:
          'Your tokens appear here, organized by category. Use filters and search to find specific tokens quickly.',
        placement: 'auto',
        mobilePlacement: 'bottom',
      },
      {
        target: '[data-tour="user-menu"]',
        content: 'Click here to open the account menu.',
        placement: 'left',
        // On mobile, user-menu is hidden, so we target the mobile menu button
        mobileTarget: '[data-tour="mobile-menu-button"]',
        mobilePlacement: 'bottom',
      },
      {
        target: '[data-tour="preferences-nav"]',
        content:
          'Click Preferences to configure alert settings, thresholds, delivery windows, contacts, webhooks, and contact groups.',
        placement: 'left',
        disableBeacon: true,
        mobileTarget:
          '[data-tour="mobile-drawer"] [data-tour="preferences-nav"]',
        mobilePlacement: 'right', // Drawer is on left, so place tooltip on right
      },
      {
        target: '[data-tour="preferences-page"]',
        content:
          'This is the Preferences page where you can configure all your alert and notification settings.',
        placement: 'bottom',
      },
      {
        target: '[data-tour="preferences-thresholds"]',
        content:
          'Set default workspace thresholds (days before expiration) when alerts should be sent. These apply to all tokens unless overridden by contact groups.',
        placement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-delivery-window"]',
        content:
          'Configure when alerts should be delivered. Alerts are only sent during this time window; outside the window they are deferred.',
        placement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-contacts-list"]',
        content:
          'View your existing contacts here. Each contact can receive alerts via email or WhatsApp.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-contacts-add"]',
        content:
          'Add new contacts here. Enter their name, email, and phone number (in E.164 format like +14155550100) for WhatsApp notifications.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-webhooks-list"]',
        content:
          'View and manage your existing webhooks here. Each webhook can be configured for Slack, Teams, Discord, PagerDuty, or generic services.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-webhooks-add"]',
        content:
          'Click "Add Webhook" to create a new webhook. Configure its name, type, and URL, then test and save it.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-contact-groups-selector"]',
        content:
          'Select an existing contact group to edit, or choose "+ Add New Group" to create a new one.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-contact-groups-contacts-channels"]',
        content:
          'When creating or editing a group, enter a name and select which contacts should receive alerts via email or WhatsApp.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-contact-groups-webhooks"]',
        content:
          'Select which webhooks should be used for this contact group. You can choose multiple webhooks to send alerts to different channels.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="preferences-contact-groups-digest"]',
        content:
          'Enable weekly digest to automatically send a summary of tokens expiring soon. You can enable it for email, WhatsApp, or webhooks.',
        placement: 'top',
        mobilePlacement: 'top',
        disableScrolling: true,
      },
      {
        target: '[data-tour="usage-nav"]',
        content:
          'View usage statistics and token counts across your workspaces. Available for managers and admins.',
        placement: 'bottom',
        isDesktopOnly: true,
      },
      {
        target: '[data-tour="usage-page"]',
        content:
          'This is the Usage page where you can monitor your alert delivery statistics and manage the alert queue.',
        placement: 'bottom',
      },
      {
        target: '[data-tour="usage-metrics"]',
        content:
          'View detailed metrics: successful deliveries (email, webhooks, WhatsApp), token counts, and monthly usage statistics per workspace.',
        placement: 'top',
        mobilePlacement: 'bottom',
      },
      {
        target: '[data-tour="usage-alert-queue"]',
        content:
          'Monitor and manage the alert queue. View pending and blocked alerts, requeue failed deliveries, and track delivery status.',
        placement: 'top',
        mobilePlacement: 'bottom',
      },
      {
        target: '[data-tour="docs-nav"]',
        content:
          'Access comprehensive documentation: API reference, token management, alerts, teams, and more.',
        placement: 'bottom',
        mobileTarget: '[data-tour="mobile-docs-nav"]',
        mobilePlacement: 'right',
      },
      {
        target: '[data-tour="help-nav"]',
        content:
          "Get help, contact support, or provide feedback. We're here to assist you!",
        placement: 'bottom',
        mobileTarget: '[data-tour="mobile-help-nav"]',
        mobilePlacement: 'right',
      },
    ];

    const firstTokenSteps = [
      {
        target: '[data-tour="token-item"]',
        content: 'Open a token to view, edit, or renew.',
        placement: 'right',
        disableBeacon: true,
      },
      {
        target: '[data-tour="alert-preferences"]',
        content: 'Configure alerts: email, webhooks, WhatsApp.',
        placement: 'left',
      },
    ];

    const workspaceSteps = [
      {
        target: '[data-tour="workspaces-nav"]',
        content: 'Manage workspaces by team/project.',
        placement: 'bottom',
        disableBeacon: true,
      },
      {
        target: '[data-tour="workspace-members"]',
        content: 'Invite members and assign roles.',
        placement: 'top',
      },
    ];

    switch (tourType) {
      case 'first-token':
        return firstTokenSteps;
      case 'workspace':
        return workspaceSteps;
      default:
        return dashboardSteps;
    }
  }, [tourType]);

  // Helper function to wait for an element to appear in the DOM
  const waitForElement = useCallback(
    (selector, { timeout = 8000, interval = 150 } = {}) => {
      return new Promise(resolve => {
        const start = Date.now();

        const check = () => {
          const el = document.querySelector(selector);
          if (el) {
            resolve(true);
            return;
          }

          if (Date.now() - start > timeout) {
            resolve(false);
            return;
          }

          setTimeout(check, interval);
        };

        check();
      });
    },
    []
  );

  // Filter and transform steps based on current viewport
  const activeSteps = useMemo(() => {
    const isMobileView =
      typeof window !== 'undefined' && window.innerWidth < 768;
    const floaterSteps = [
      '[data-tour="preferences-contacts-list"]',
      '[data-tour="preferences-contacts-add"]',
      '[data-tour="preferences-webhooks-list"]',
      '[data-tour="preferences-webhooks-add"]',
      '[data-tour="preferences-contact-groups-selector"]',
      '[data-tour="preferences-contact-groups-contacts-channels"]',
      '[data-tour="preferences-contact-groups-webhooks"]',
      '[data-tour="preferences-contact-groups-digest"]',
    ];

    return steps
      .filter(step => {
        if (isMobileView && step.isDesktopOnly) return false;
        if (!isMobileView && step.isMobileOnly) return false;
        return true;
      })
      .map(step => {
        const target =
          isMobileView && step.mobileTarget ? step.mobileTarget : step.target;
        const placement =
          isMobileView && step.mobilePlacement
            ? step.mobilePlacement
            : step.placement || 'bottom';

        const transformedStep = {
          ...step,
          target,
          placement,
        };

        // Only apply floaterProps on mobile for the sensitive steps (contacts, webhooks, contact groups sub-steps).
        // Desktop keeps default behaviour (no floaterProps changes, keeps disableScrolling).
        if (
          isMobileView &&
          (floaterSteps.includes(step.target) ||
            floaterSteps.includes(target)) &&
          step.floaterProps
        ) {
          transformedStep.floaterProps = step.floaterProps;
        }

        return transformedStep;
      });
  }, [steps]);

  // Delay start until first target exists and check localStorage
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const key = `tt_tour_${tourType}`;
    const hasCompleted = localStorage.getItem(key) === 'true';

    // If parent didn't ask to run the tour, keep it stopped.
    if (!run) {
      setIsRunning(false);
      return;
    }

    // If tour has already completed and we don't force it, don't start.
    if (!forceRun && hasCompleted) {
      setIsRunning(false);
      return;
    }

    let cancelled = false;

    const findFirstAvailableStep = () => {
      // On mobile, always start at step 0 (mobile-menu-button)
      const isMobileView =
        typeof window !== 'undefined' && window.innerWidth < 768;
      if (isMobileView && activeSteps.length > 0) {
        const firstStep = activeSteps[0];
        if (firstStep?.target === '[data-tour="mobile-menu-button"]') {
          const element = document.querySelector(firstStep.target);
          if (element) {
            const style = window.getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            if (
              style.display !== 'none' &&
              style.visibility !== 'hidden' &&
              style.opacity !== '0' &&
              rect.width > 0 &&
              rect.height > 0
            ) {
              return 0; // Start at mobile menu button
            }
          }
        }
      }

      // Find the first step in activeSteps whose target element exists and is visible
      for (let i = 0; i < activeSteps.length; i++) {
        const target = activeSteps[i]?.target;
        if (!target) {
          return i; // Step without target, start here
        }

        const element = document.querySelector(target);
        if (element) {
          // Check if element is visible (not hidden by display: none or similar)
          const style = window.getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          if (
            style.display !== 'none' &&
            style.visibility !== 'hidden' &&
            style.opacity !== '0' &&
            rect.width > 0 &&
            rect.height > 0
          ) {
            return i;
          }
        } else {
          // For mobile menu items in drawer, check if menu button exists
          if (
            target === '[data-tour="mobile-tokens-nav"]' ||
            target === '[data-tour="mobile-docs-nav"]' ||
            target === '[data-tour="mobile-help-nav"]'
          ) {
            const menuButton = document.querySelector(
              '[data-tour="mobile-menu-button"]'
            );
            if (menuButton) {
              // Element is in drawer, which might not be open yet - that's OK, we'll open it
              return i;
            }
          }
        }
      }
      return 0; // Fallback to first step
    };

    const start = () => {
      if (cancelled) return;
      const firstAvailableIndex = findFirstAvailableStep();
      setStepIndex(firstAvailableIndex);
      setIsRunning(true);
    };

    if (activeSteps.length === 0) {
      setIsRunning(false);
      return;
    }

    const firstTarget = activeSteps[0]?.target;

    // No target for first step -> just start
    if (!firstTarget) {
      start();
      return;
    }

    // Wait a bit for DOM to settle, then find first available step
    let tries = 0;
    const maxTries = 30; // Increased from 20 to give more time

    const timer = setInterval(() => {
      const firstAvailableIndex = findFirstAvailableStep();
      const found =
        firstAvailableIndex === 0 && !!document.querySelector(firstTarget);

      if (found || tries++ > maxTries) {
        clearInterval(timer);
        start();
      }
    }, 150);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [run, activeSteps, tourType, forceRun]);

  // Ref to track if we're currently processing a step to prevent infinite loops
  const isProcessingRef = useRef(false);

  const closeMobileNav = useCallback(() => {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('tt:close-mobile-nav'));
    }
  }, []);

  const wait = useCallback(
    (ms = 100) => new Promise(resolve => setTimeout(resolve, ms)),
    []
  );

  const ensureMobileDrawerClosed = useCallback(async () => {
    if (typeof window === 'undefined') return;
    if (window.innerWidth >= 768) return;

    // First, dispatch the custom event to trigger Navigation.jsx's listener
    closeMobileNav();
    await wait(100);

    // Then try multiple aggressive methods to ensure it's closed
    for (let attempt = 0; attempt < 8; attempt++) {
      const drawer = document.querySelector('[data-tour="mobile-drawer"]');
      const drawerVisible =
        drawer && window.getComputedStyle(drawer).display !== 'none';

      if (!drawer || !drawerVisible) {
        // Drawer is closed, verify and exit
        await wait(50);
        const verifyDrawer = document.querySelector(
          '[data-tour="mobile-drawer"]'
        );
        const verifyVisible =
          verifyDrawer &&
          window.getComputedStyle(verifyDrawer).display !== 'none';
        if (!verifyDrawer || !verifyVisible) {
          break; // Confirmed closed
        }
      }

      // Try multiple methods simultaneously
      closeMobileNav(); // Dispatch event again

      const overlay = document.querySelector(
        '[data-tour="mobile-drawer-overlay"]'
      );
      if (overlay instanceof HTMLElement) {
        overlay.click();
        overlay.dispatchEvent(
          new MouseEvent('click', { bubbles: true, cancelable: true })
        );
      }

      const menuButton = document.querySelector(
        '[data-tour="mobile-menu-button"]'
      );
      if (menuButton instanceof HTMLElement) {
        // Only click if drawer is actually open (aria-expanded check)
        const isExpanded = menuButton.getAttribute('aria-expanded') === 'true';
        if (isExpanded) {
          menuButton.click();
        }
      }

      // Try ESC key
      const escEvent = new KeyboardEvent('keydown', {
        key: 'Escape',
        code: 'Escape',
        keyCode: 27,
        which: 27,
        bubbles: true,
        cancelable: true,
      });
      document.dispatchEvent(escEvent);

      await wait(100);
    }

    // Final cleanup: ensure scrolling is enabled
    try {
      document.body.style.overflow = '';
      document.body.style.position = '';
      document.documentElement.style.overflow = '';
      document.documentElement.style.position = '';
    } catch (err) {
      // Ignore errors
    }
  }, [closeMobileNav, wait]);

  /**
   * Mobile-only helper for the “preferences sub-steps” (contacts / webhooks / contact groups).
   *
   * Behaviour:
   * - Scrolls the target into view centered.
   * - Then nudges it down so its top sits around 55% of viewport height.
   *   => leaves enough room above for the Joyride tooltip (placement "top").
   */
  const scrollTargetWithTooltipSpaceMobile = useCallback(
    (selector, { delay = 100 } = {}) => {
      if (typeof window === 'undefined') return;
      if (window.innerWidth >= 768) return;

      setTimeout(() => {
        const el = document.querySelector(selector);
        if (!el) return;

        // First center the element
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });

        // Then adjust so there is extra room above for the tooltip
        setTimeout(() => {
          const rect = el.getBoundingClientRect();
          const viewportHeight = window.innerHeight;

          // We want the element's top to be slightly below the center
          const desiredTop = viewportHeight * 0.55; // 55% down the screen
          const deltaScroll = rect.top - desiredTop;

          // Move the viewport so the element ends at desiredTop
          window.scrollBy({ top: deltaScroll, behavior: 'smooth' });

          // Let Joyride recompute positions
          setTimeout(() => {
            window.dispatchEvent(new Event('resize'));
          }, 300);
        }, 400);
      }, delay);
    },
    []
  );

  const handleJoyrideCallback = useCallback(
    async data => {
      const { action, index, status, type, step } = data;

      // Prevent concurrent processing
      if (isProcessingRef.current && type === EVENTS.STEP_BEFORE) {
        return;
      }

      // Note: index here refers to activeSteps index, not original steps index

      // Tour finished or skipped
      if (status === STATUS.FINISHED || status === STATUS.SKIPPED) {
        setIsRunning(false);
        setStepIndex(0);

        // Release menu lock when tour ends
        window.dispatchEvent(
          new CustomEvent('tt:tour-menu-state', {
            detail: { isActive: false, keepMenuOpen: false },
          })
        );

        try {
          trackEvent('product_tour_completed', {
            tour_type: tourType,
            status: status === STATUS.FINISHED ? 'completed' : 'skipped',
            steps_completed: index + 1,
            total_steps: activeSteps.length,
          });

          if (typeof window !== 'undefined') {
            localStorage.setItem(`tt_tour_${tourType}`, 'true');
          }
        } catch (_) {}

        onTourComplete?.(status === STATUS.FINISHED);
        return;
      }

      // Before each step is shown
      if (type === EVENTS.STEP_BEFORE) {
        // Prevent concurrent processing - but reset quickly to avoid blocking UI
        if (isProcessingRef.current) {
          // Reset immediately if stuck
          isProcessingRef.current = false;
        }
        isProcessingRef.current = true;

        // Always reset after a short delay to prevent blocking
        setTimeout(() => {
          isProcessingRef.current = false;
        }, 500);

        try {
          // Open mobile navigation drawer ONLY when we reach mobile navigation items (NOT for mobile-menu-button step itself)
          // Step 1 should just point to the button without opening it
          const isMobileView =
            typeof window !== 'undefined' && window.innerWidth < 768;

          if (
            step?.target &&
            (step.target === '[data-tour="mobile-tokens-nav"]' ||
              step.target === '[data-tour="mobile-docs-nav"]' ||
              step.target === '[data-tour="mobile-help-nav"]' ||
              (isMobileView && step.target === '[data-tour="preferences-nav"]'))
          ) {
            // Open drawer non-blocking
            setTimeout(() => {
              try {
                const menuButton = document.querySelector(
                  '[data-tour="mobile-menu-button"]'
                );
                if (menuButton) {
                  // Check if drawer is already open by looking for the drawer element
                  const drawer = document.querySelector(
                    '[data-tour="mobile-drawer"]'
                  );
                  const drawerVisible =
                    drawer &&
                    window.getComputedStyle(drawer).display !== 'none';
                  if (!drawer || !drawerVisible) {
                    menuButton.click();
                  }
                }
              } catch (err) {
                // Ignore errors
              }
            }, 100);
          }

          // For add-token-form step (step 3), ensure drawer is closed (non-blocking)
          if (step?.target === '[data-tour="add-token-form"]') {
            setTimeout(() => {
              ensureMobileDrawerClosed().catch(() => {
                // Ignore errors
              });
            }, 100);
          }

          // Open user menu when we reach that step (only if not already open)
          // Ensure page is scrollable before opening menu to prevent getting stuck
          if (step?.target === '[data-tour="user-menu"]') {
            // Re-enable scrolling immediately (non-blocking)
            try {
              document.body.style.overflow = '';
              document.body.style.position = '';
              document.documentElement.style.overflow = '';
              document.documentElement.style.position = '';
            } catch (err) {
              // Ignore
            }

            // Signal to Navigation that tour needs menu to stay open
            window.dispatchEvent(
              new CustomEvent('tt:tour-menu-state', {
                detail: { isActive: true, keepMenuOpen: true },
              })
            );

            // Close mobile drawer and open user menu in background (non-blocking)
            setTimeout(() => {
              try {
                const isMobileNow =
                  typeof window !== 'undefined' && window.innerWidth < 768;
                if (isMobileNow) {
                  // On mobile, we target mobile-menu-button instead, so this block is skipped
                  // But just in case, ensure drawer is closed
                  closeMobileNav();
                  return;
                }

                const menuButton = document.querySelector(
                  '[data-tour="user-menu"]'
                );
                if (menuButton) {
                  // Check if menu is already open
                  const isExpanded =
                    menuButton.getAttribute('aria-expanded') === 'true';
                  if (!isExpanded) {
                    setTimeout(() => {
                      try {
                        menuButton.click();
                      } catch (err) {
                        // Ignore errors
                      }
                    }, 200);
                  }
                }
              } catch (err) {
                // Ignore errors
              }
            }, 100);
          }

          // For mobile-menu-button step, ensure drawer is closed
          if (step?.target === '[data-tour="mobile-menu-button"]') {
            setTimeout(() => {
              ensureMobileDrawerClosed().catch(() => {});
            }, 100);
          }

          // For preferences-nav, ensure menu/drawer is open
          if (step?.target && step.target.includes('preferences-nav')) {
            const isMobileNow =
              typeof window !== 'undefined' && window.innerWidth < 768;

            if (isMobileNow) {
              setTimeout(() => {
                const drawer = document.querySelector(
                  '[data-tour="mobile-drawer"]'
                );
                const drawerVisible =
                  drawer && window.getComputedStyle(drawer).display !== 'none';
                if (!drawer || !drawerVisible) {
                  const menuButton = document.querySelector(
                    '[data-tour="mobile-menu-button"]'
                  );
                  if (menuButton) menuButton.click();
                }
              }, 100);
            } else {
              // Desktop: ensure user menu is open and locked
              window.dispatchEvent(
                new CustomEvent('tt:tour-menu-state', {
                  detail: { isActive: true, keepMenuOpen: true },
                })
              );

              const menuButton = document.querySelector(
                '[data-tour="user-menu"]'
              );
              if (
                menuButton &&
                menuButton.getAttribute('aria-expanded') !== 'true'
              ) {
                menuButton.click();
              }
            }
          }

          // Navigate to /preferences when we reach the preferences-page step (going forward)
          if (step?.target === '[data-tour="preferences-page"]') {
            // If we're going backward (PREV) from preferences-page, navigate back to dashboard
            if (
              action === ACTIONS.PREV &&
              typeof window !== 'undefined' &&
              window.location.pathname === '/preferences'
            ) {
              setIsRunning(false);

              // Navigate back to dashboard
              navigate('/dashboard');

              // Wait for dashboard to load and preferences-nav element to be available
              const prevStep = activeSteps[index - 1];
              if (
                prevStep?.target &&
                prevStep.target.includes('preferences-nav')
              ) {
                const found = await waitForElement(prevStep.target, {
                  timeout: 8000,
                  interval: 150,
                });

                if (found) {
                  await wait(300);
                }
              } else {
                // Fallback: just wait a bit
                await wait(500);
              }

              // Move to previous step
              setStepIndex(index - 1);
              setIsRunning(true);
              return;
            }

            // If we're going forward and not on preferences page yet, navigate there
            if (
              action !== ACTIONS.PREV &&
              typeof window !== 'undefined' &&
              window.location.pathname !== '/preferences'
            ) {
              setIsRunning(false);

              // Trigger navigation
              navigate('/preferences');

              // Wait for the preferences page root element to be fully mounted
              const found = await waitForElement(step.target, {
                timeout: 8000,
                interval: 150,
              });

              // Additional wait to ensure React has fully rendered the component
              if (found) {
                await wait(300);
              }

              // Resume this same step (index)
              setStepIndex(index);
              setIsRunning(true);
              return;
            }
          }

          // Navigate to /usage when we reach the usage-page step (going forward)
          if (step?.target === '[data-tour="usage-page"]') {
            // If we're going backward (PREV) from usage-page, navigate back appropriately
            if (
              action === ACTIONS.PREV &&
              typeof window !== 'undefined' &&
              window.location.pathname === '/usage'
            ) {
              setIsRunning(false);

              // Determine where to navigate based on previous step
              const prevStep = activeSteps[index - 1];
              let targetPath = '/preferences'; // Default to preferences (mobile flow)

              // If previous step is usage-nav (desktop) or anything on dashboard, go to dashboard
              if (prevStep?.target === '[data-tour="usage-nav"]') {
                targetPath = '/dashboard';
              }

              // Navigate to the appropriate page
              navigate(targetPath);

              // Wait for the page to load and previous element to be available
              if (prevStep?.target) {
                const found = await waitForElement(prevStep.target, {
                  timeout: 8000,
                  interval: 150,
                });

                if (found) {
                  await wait(300);
                }
              } else {
                // Fallback: just wait a bit
                await wait(500);
              }

              // Move to previous step
              setStepIndex(index - 1);
              setIsRunning(true);
              return;
            }

            // If we're going forward and not on usage page yet, navigate there
            if (
              action !== ACTIONS.PREV &&
              typeof window !== 'undefined' &&
              window.location.pathname !== '/usage'
            ) {
              setIsRunning(false);

              // Trigger navigation
              navigate('/usage');

              // Wait for the usage page root element to be fully mounted
              const found = await waitForElement(step.target, {
                timeout: 8000,
                interval: 150,
              });

              // Additional wait to ensure React has fully rendered the component
              if (found) {
                await wait(300);
              }

              // Resume this same step (index)
              setStepIndex(index);
              setIsRunning(true);
              return;
            }
          }

          // Manual scroll for specific steps
          if (step?.target) {
            const { target } = step;
            const isMobileNow =
              typeof window !== 'undefined' && window.innerWidth < 768;

            // Handle all preferences sub-steps with generic scrolling (steps 12–19 on mobile)
            const preferencesSubSteps = [
              '[data-tour="preferences-contacts-list"]',
              '[data-tour="preferences-contacts-add"]',
              '[data-tour="preferences-webhooks-list"]',
              '[data-tour="preferences-webhooks-add"]',
              '[data-tour="preferences-contact-groups-selector"]',
              '[data-tour="preferences-contact-groups-contacts-channels"]',
              '[data-tour="preferences-contact-groups-webhooks"]',
              '[data-tour="preferences-contact-groups-digest"]',
            ];

            if (preferencesSubSteps.includes(target)) {
              if (isMobileNow) {
                // Use our helper to keep the element slightly below center
                scrollTargetWithTooltipSpaceMobile(target, { delay: 100 });
              } else {
                // Desktop: center the element (unchanged)
                setTimeout(() => {
                  const el = document.querySelector(target);
                  if (!el) return;
                  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                  setTimeout(
                    () => window.dispatchEvent(new Event('resize')),
                    400
                  );
                }, 100);
              }
            }

            // Handle token-list step - ensure it's positioned well with space for tooltip
            if (target === '[data-tour="token-list"]') {
              if (isMobileNow) {
                // Mobile: scroll to start of element
                setTimeout(() => {
                  const el = document.querySelector(target);
                  if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    setTimeout(
                      () => window.dispatchEvent(new Event('resize')),
                      400
                    );
                  }
                }, 100);
              } else {
                // Desktop: ensure proper positioning with space for left-side tooltip and footer
                setTimeout(() => {
                  const el = document.querySelector(target);
                  if (el) {
                    const rect = el.getBoundingClientRect();
                    const absoluteTop = rect.top + window.pageYOffset;
                    const navBarHeight = 78;
                    const padding = 100; // Extra padding to account for tooltip and footer

                    // Calculate target position: element should be positioned with enough space
                    const targetPosition = navBarHeight + padding;
                    const targetScrollTop = Math.max(
                      0,
                      absoluteTop - targetPosition
                    );

                    // Scroll to ensure visibility with space for tooltip
                    window.scrollTo({
                      top: targetScrollTop,
                      behavior: 'smooth',
                    });

                    // Verify after scroll and adjust if needed
                    setTimeout(() => {
                      const newRect = el.getBoundingClientRect();
                      const currentScroll = window.pageYOffset;

                      // Check if we need more space at the bottom (account for footer ~100px)
                      const viewportHeight = window.innerHeight;
                      const footerHeight = 100; // Approximate footer height
                      const tooltipSpace = 300; // Space needed for tooltip
                      const bottomSpace = viewportHeight - newRect.bottom;

                      // If not enough space at bottom, scroll up more
                      if (bottomSpace < footerHeight + tooltipSpace) {
                        const additionalScroll =
                          footerHeight + tooltipSpace - bottomSpace;
                        window.scrollTo({
                          top: Math.max(0, currentScroll - additionalScroll),
                          behavior: 'smooth',
                        });
                      }

                      window.dispatchEvent(new Event('resize'));
                    }, 500);
                  }
                }, 100);
              }
            }

            // Handle preferences-thresholds step similarly
            if (target === '[data-tour="preferences-thresholds"]') {
              setTimeout(() => {
                const el = document.querySelector(target);
                if (el) {
                  el.scrollIntoView({ behavior: 'smooth', block: 'center' });

                  setTimeout(
                    () => window.dispatchEvent(new Event('resize')),
                    400
                  );
                  setTimeout(
                    () => window.dispatchEvent(new Event('resize')),
                    800
                  );
                }
              }, 100);
            }

            // Handle preferences-delivery-window step similarly
            if (target === '[data-tour="preferences-delivery-window"]') {
              setTimeout(() => {
                const el = document.querySelector(target);
                if (el) {
                  el.scrollIntoView({ behavior: 'smooth', block: 'center' });

                  setTimeout(
                    () => window.dispatchEvent(new Event('resize')),
                    400
                  );
                  setTimeout(
                    () => window.dispatchEvent(new Event('resize')),
                    800
                  );
                }
              }, 100);
            }

            if (isMobileNow) {
              // Scroll to preferences-nav inside drawer
              if (target && target.includes('preferences-nav')) {
                setTimeout(() => {
                  const el = document.querySelector(target);
                  if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    setTimeout(
                      () => window.dispatchEvent(new Event('resize')),
                      400
                    );
                  }
                }, 400); // Wait for drawer animation
              }

              // Scroll usage page sections slightly into view
              const usageTargets = [
                '[data-tour="usage-page"]',
                '[data-tour="usage-metrics"]',
                '[data-tour="usage-alert-queue"]',
              ];
              if (usageTargets.includes(target)) {
                setTimeout(() => {
                  const el = document.querySelector(target);
                  if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    setTimeout(
                      () => window.dispatchEvent(new Event('resize')),
                      400
                    );
                  }
                }, 100);
              }
            }
          }

          // Manual scroll to center import/export buttons on mobile
          if (
            [
              '[data-tour="import-tokens"]',
              '[data-tour="export-tokens"]',
            ].includes(step?.target)
          ) {
            const isMobileNow =
              typeof window !== 'undefined' && window.innerWidth < 768;
            if (isMobileNow) {
              setTimeout(() => {
                const element = document.querySelector(step.target);
                if (element) {
                  // Center the element vertically
                  element.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center',
                  });

                  // Force Joyride to update positioning after scroll
                  setTimeout(() => {
                    window.dispatchEvent(new Event('resize'));
                  }, 400);
                }
              }, 100); // Wait for Joyride to start its own scroll/render
            }
          }
        } catch (error) {
          // Log error but don't crash
          logger.warn('Error in STEP_BEFORE:', error);
        } finally {
          // Always reset processing flag after a delay to allow step to render
          // Use a shorter delay to prevent blocking
          setTimeout(() => {
            isProcessingRef.current = false;
          }, 300);
        }

        return;
      }

      // TARGET_NOT_FOUND: for preferences-* and usage-* steps, wait & retry; otherwise skip
      if (type === EVENTS.TARGET_NOT_FOUND) {
        // For preferences-nav, if we're already on preferences page, skip to next step
        if (
          step?.target &&
          step.target.includes('preferences-nav') &&
          window.location.pathname === '/preferences'
        ) {
          // We've already navigated, move to next step
          const nextIndex = action === ACTIONS.PREV ? index - 1 : index + 1;
          setStepIndex(nextIndex);
          return;
        }

        // For preferences-nav, ensure menu is open first
        if (step?.target && step.target.includes('preferences-nav')) {
          const isMobileNow =
            typeof window !== 'undefined' && window.innerWidth < 768;

          if (isMobileNow) {
            // Try to open mobile drawer if target not found
            const menuButton = document.querySelector(
              '[data-tour="mobile-menu-button"]'
            );
            if (menuButton) {
              const drawer = document.querySelector(
                '[data-tour="mobile-drawer"]'
              );
              const drawerVisible =
                drawer && window.getComputedStyle(drawer).display !== 'none';

              // Only click if drawer is closed
              if (!drawer || !drawerVisible) {
                menuButton.click();
              }

              // Wait a bit for drawer to open/render, then retry
              setIsRunning(false);
              const found = await waitForElement(step.target, {
                timeout: 2000,
                interval: 100,
              });
              if (found) {
                setStepIndex(index);
                setIsRunning(true);
                return;
              }
            }
          } else {
            const menuButton = document.querySelector(
              '[data-tour="user-menu"]'
            );
            if (menuButton) {
              menuButton.click();
              // Wait a bit for menu to open, then retry
              setIsRunning(false);
              const found = await waitForElement(step.target, {
                timeout: 2000,
                interval: 100,
              });
              if (found) {
                setStepIndex(index);
                setIsRunning(true);
                return;
              }
            }
          }
        }

        // For preferences-page and other preferences-* steps (not preferences-nav), wait for them to load
        if (
          step?.target &&
          step.target.startsWith('[data-tour="preferences-"]') &&
          step.target !== '[data-tour="preferences-nav"]'
        ) {
          // Likely still loading; wait a bit for this exact element
          setIsRunning(false);
          const found = await waitForElement(step.target, {
            timeout: 4000,
            interval: 150,
          });

          if (found) {
            setStepIndex(index); // stay on the same step
            setIsRunning(true);
            return;
          }
        }

        // For usage-* steps, wait for them to load
        if (step?.target && step.target.startsWith('[data-tour="usage-"]')) {
          // Likely still loading; wait a bit for this exact element
          setIsRunning(false);
          const found = await waitForElement(step.target, {
            timeout: 4000,
            interval: 150,
          });

          if (found) {
            setStepIndex(index); // stay on the same step
            setIsRunning(true);
            return;
          }
        }

        // For mobile: if element is not found and not visible, find next available step
        if (step?.target) {
          const element = document.querySelector(step.target);
          if (element) {
            const style = window.getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            const isHidden =
              style.display === 'none' ||
              style.visibility === 'hidden' ||
              style.opacity === '0' ||
              rect.width === 0 ||
              rect.height === 0;

            if (isHidden) {
              // Element exists but is hidden (e.g., mobile-only element on desktop or vice versa)
              // Find next available step
              const direction = action === ACTIONS.PREV ? -1 : 1;
              let nextIndex = index + direction;

              // Look for next available step (up to 5 steps ahead/behind)
              for (
                let i = 0;
                i < 5 && nextIndex >= 0 && nextIndex < activeSteps.length;
                i++
              ) {
                const nextStep = activeSteps[nextIndex];
                if (!nextStep?.target) {
                  // Step without target, use it
                  setStepIndex(nextIndex);
                  return;
                }

                const nextElement = document.querySelector(nextStep.target);
                if (nextElement) {
                  const nextStyle = window.getComputedStyle(nextElement);
                  const nextRect = nextElement.getBoundingClientRect();
                  if (
                    nextStyle.display !== 'none' &&
                    nextStyle.visibility !== 'hidden' &&
                    nextStyle.opacity !== '0' &&
                    nextRect.width > 0 &&
                    nextRect.height > 0
                  ) {
                    setStepIndex(nextIndex);
                    return;
                  }
                }

                nextIndex += direction;
              }
            }
          }
        }

        // Fallback: skip to next/prev step
        const nextIndex = action === ACTIONS.PREV ? index - 1 : index + 1;
        setStepIndex(nextIndex);
        return;
      }

      // After each step
      if (type === EVENTS.STEP_AFTER) {
        const nextIndex = action === ACTIONS.PREV ? index - 1 : index + 1;
        const nextStep = activeSteps[nextIndex];

        // Release menu lock when going backward from user-menu or preferences-nav
        if (
          action === ACTIONS.PREV &&
          (step?.target === '[data-tour="user-menu"]' ||
            (step?.target && step.target.includes('preferences-nav')))
        ) {
          window.dispatchEvent(
            new CustomEvent('tt:tour-menu-state', {
              detail: { isActive: false, keepMenuOpen: false },
            })
          );
        }

        // Special case: after mobile-menu-button step, open drawer for mobile-tokens-nav
        if (
          step?.target === '[data-tour="mobile-menu-button"]' &&
          nextStep?.target === '[data-tour="mobile-tokens-nav"]'
        ) {
          // Open the drawer now (it wasn't opened in STEP_BEFORE for step 1)
          setTimeout(async () => {
            try {
              const menuButton = document.querySelector(
                '[data-tour="mobile-menu-button"]'
              );
              if (menuButton) {
                // Check if drawer is already open
                const drawer = document.querySelector(
                  '[data-tour="mobile-drawer"]'
                );
                const drawerVisible =
                  drawer && window.getComputedStyle(drawer).display !== 'none';

                if (!drawer || !drawerVisible) {
                  // Open the drawer
                  menuButton.click();
                  await wait(600);
                }
              }

              // Wait for target element to be visible
              let attempts = 0;
              while (attempts < 15) {
                const element = document.querySelector(nextStep.target);
                if (element) {
                  const style = window.getComputedStyle(element);
                  const rect = element.getBoundingClientRect();
                  if (
                    style.display !== 'none' &&
                    style.visibility !== 'hidden' &&
                    style.opacity !== '0' &&
                    rect.width > 0 &&
                    rect.height > 0
                  ) {
                    // Element is visible, proceed to next step
                    if (nextIndex >= 0 && nextIndex < activeSteps.length) {
                      setStepIndex(nextIndex);
                    }
                    return;
                  }
                }
                await wait(100);
                attempts++;
              }

              // If we couldn't find the element, still proceed to avoid getting stuck
              if (nextIndex >= 0 && nextIndex < activeSteps.length) {
                setStepIndex(nextIndex);
              }
            } catch (err) {
              logger.warn('Error in mobile-tokens-nav transition:', err);
              // Always proceed to avoid getting stuck
              if (nextIndex >= 0 && nextIndex < activeSteps.length) {
                setStepIndex(nextIndex);
              }
            }
          }, 100);
          return; // Don't proceed with default behavior
        }

        // Special case: after mobile-menu-button step, open drawer for preferences-nav
        if (
          step?.target === '[data-tour="mobile-menu-button"]' &&
          nextStep?.target &&
          nextStep.target.includes('preferences-nav')
        ) {
          setTimeout(async () => {
            try {
              const menuButton = document.querySelector(
                '[data-tour="mobile-menu-button"]'
              );
              if (menuButton) {
                const drawer = document.querySelector(
                  '[data-tour="mobile-drawer"]'
                );
                const drawerVisible =
                  drawer && window.getComputedStyle(drawer).display !== 'none';

                if (!drawer || !drawerVisible) {
                  menuButton.click();
                  await wait(800);
                }
              }

              // Proceed to next step
              if (nextIndex >= 0 && nextIndex < activeSteps.length) {
                setStepIndex(nextIndex);
              }
            } catch (err) {
              // proceed anyway
              if (nextIndex >= 0 && nextIndex < activeSteps.length) {
                setStepIndex(nextIndex);
              }
            }
          }, 100);
          return;
        }

        // Special case: after mobile-tokens-nav step, close drawer before moving to next step
        // (unless next step is also in the drawer)
        if (
          step?.target === '[data-tour="mobile-tokens-nav"]' &&
          nextStep?.target &&
          nextStep.target !== '[data-tour="mobile-docs-nav"]' &&
          nextStep.target !== '[data-tour="mobile-help-nav"]'
        ) {
          if (typeof window !== 'undefined' && window.innerWidth < 768) {
            setIsRunning(false);
            await wait(100);
            await ensureMobileDrawerClosed();
            // Wait a bit more to ensure drawer animation completes
            await wait(200);
            if (nextIndex >= 0 && nextIndex < activeSteps.length) {
              setStepIndex(nextIndex);
            }
            setIsRunning(true);

            trackEvent('product_tour_step', {
              tour_type: tourType,
              step_index: nextIndex,
              step_total: activeSteps.length,
              action: action === ACTIONS.PREV ? 'back' : 'next',
            });
            return;
          }
        }

        // Special case: after export-tokens step, force transition to token-list step
        // react-joyride sometimes gets stuck here, so we need to manually advance
        if (step?.target === '[data-tour="export-tokens"]') {
          // Re-enable scrolling immediately
          try {
            document.body.style.overflow = '';
            document.body.style.position = '';
            document.documentElement.style.overflow = '';
            document.documentElement.style.position = '';
          } catch (err) {
            // Ignore errors
          }

          // If going back, scroll up to import-tokens
          if (action === ACTIONS.PREV) {
            setTimeout(() => {
              try {
                const element = document.querySelector(
                  '[data-tour="import-tokens"]'
                );
                if (element) {
                  element.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center',
                  });
                }
              } catch (err) {}
            }, 200);
          } else {
            // Scroll to token-list in background (non-blocking)
            setTimeout(() => {
              try {
                const element = document.querySelector(
                  '[data-tour="token-list"]'
                );
                if (element) {
                  // Use 'start' to scroll to the top of the list, better for long lists
                  element.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start',
                  });
                }
              } catch (err) {
                // Ignore errors
              }
            }, 200);
          }

          // Only force transition if we are moving forward (not back)
          if (
            action !== ACTIONS.PREV &&
            nextIndex >= 0 &&
            nextIndex < activeSteps.length
          ) {
            // Force transition immediately - use multiple methods to ensure it works
            setIsRunning(true);
            setStepIndex(nextIndex);

            // Also set it in next frame as backup
            requestAnimationFrame(() => {
              setIsRunning(true);
              setStepIndex(nextIndex);
            });

            // Track the event
            trackEvent('product_tour_step', {
              tour_type: tourType,
              step_index: nextIndex,
              step_total: activeSteps.length,
              action: action === ACTIONS.PREV ? 'back' : 'next',
            });

            return; // Prevent default handler to avoid conflicts
          }
        }

        // Special case: If going BACK from token-list to export-tokens
        if (
          step?.target === '[data-tour="token-list"]' &&
          action === ACTIONS.PREV
        ) {
          setTimeout(() => {
            const exportBtn = document.querySelector(
              '[data-tour="export-tokens"]'
            );
            if (exportBtn) {
              exportBtn.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
          }, 100);
        }

        // Special case: If going BACK from preferences-page to preferences-nav
        if (
          step?.target &&
          step.target.startsWith('[data-tour="preferences-"]') &&
          action === ACTIONS.PREV
        ) {
          if (
            nextStep?.target === '[data-tour="preferences-nav"]' ||
            nextStep?.target.includes('preferences-nav')
          ) {
            // We need to re-open the menu (desktop) or drawer (mobile)
            const isMobileNow =
              typeof window !== 'undefined' && window.innerWidth < 768;
            if (isMobileNow) {
              setTimeout(async () => {
                const menuButton = document.querySelector(
                  '[data-tour="mobile-menu-button"]'
                );
                if (menuButton) {
                  const drawer = document.querySelector(
                    '[data-tour="mobile-drawer"]'
                  );
                  const drawerVisible =
                    drawer &&
                    window.getComputedStyle(drawer).display !== 'none';
                  if (!drawer || !drawerVisible) {
                    menuButton.click();
                    await wait(500);
                  }
                }
              }, 100);
            } else {
              setTimeout(() => {
                const menuButton = document.querySelector(
                  '[data-tour="user-menu"]'
                );
                if (menuButton) menuButton.click();
              }, 100);
            }
          }
        }

        // Special case: after token-list step, force transition immediately
        // react-joyride sometimes gets stuck here, so we need to manually advance
        if (step?.target === '[data-tour="token-list"]') {
          // Re-enable scrolling immediately
          try {
            document.body.style.overflow = '';
            document.body.style.position = '';
            document.documentElement.style.overflow = '';
            document.documentElement.style.position = '';
          } catch (err) {
            // Ignore
          }

          // Only force transition if we are moving forward (not back)
          if (
            action !== ACTIONS.PREV &&
            nextIndex >= 0 &&
            nextIndex < activeSteps.length
          ) {
            // Force transition using setTimeout to break out of current event loop
            setTimeout(() => {
              setIsRunning(true);
              setStepIndex(nextIndex);
            }, 10);

            // Track the event
            trackEvent('product_tour_step', {
              tour_type: tourType,
              step_index: nextIndex,
              step_total: activeSteps.length,
              action: action === ACTIONS.PREV ? 'back' : 'next',
            });

            return; // Prevent default handler to avoid conflicts
          }
        }

        // Special case: If going BACK from preferences-nav to user-menu (Desktop)
        if (
          step?.target &&
          step.target.includes('preferences-nav') &&
          nextStep?.target === '[data-tour="user-menu"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(async () => {
            // Close the menu to reset state
            const menuButton = document.querySelector(
              '[data-tour="user-menu"]'
            );
            if (menuButton) {
              const isExpanded =
                menuButton.getAttribute('aria-expanded') === 'true';
              if (isExpanded) {
                menuButton.click();
                await wait(200);
              }
            }

            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from preferences-nav to token-list
        if (
          step?.target &&
          step.target.includes('preferences-nav') &&
          nextStep?.target === '[data-tour="token-list"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(async () => {
            // Close menu if open
            if (typeof window !== 'undefined' && window.innerWidth < 768) {
              await ensureMobileDrawerClosed();
            } else {
              const menuButton = document.querySelector(
                '[data-tour="user-menu"]'
              );
              if (menuButton) {
                const isExpanded =
                  menuButton.getAttribute('aria-expanded') === 'true';
                if (isExpanded) {
                  menuButton.click();
                  await wait(200);
                }
              }
            }

            // Scroll token list into view
            const tokenList = document.querySelector(
              '[data-tour="token-list"]'
            );
            if (tokenList) {
              tokenList.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }

            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from preferences-page to preferences-nav
        if (
          step?.target === '[data-tour="preferences-page"]' &&
          nextStep?.target &&
          nextStep.target.includes('preferences-nav') &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(async () => {
            if (window.location.pathname !== '/dashboard') {
              navigate('/dashboard');
              await wait(500);
            }

            // Re-open menu/drawer
            if (typeof window !== 'undefined' && window.innerWidth < 768) {
              const menuButton = document.querySelector(
                '[data-tour="mobile-menu-button"]'
              );
              if (menuButton) {
                const drawer = document.querySelector(
                  '[data-tour="mobile-drawer"]'
                );
                const drawerVisible =
                  drawer && window.getComputedStyle(drawer).display !== 'none';
                if (!drawer || !drawerVisible) {
                  menuButton.click();
                  await wait(500);
                }
              }
            } else {
              const menuButton = document.querySelector(
                '[data-tour="user-menu"]'
              );
              if (menuButton) {
                const isExpanded =
                  menuButton.getAttribute('aria-expanded') === 'true';
                if (!isExpanded) {
                  menuButton.click();
                  await wait(200);
                }
              }
            }

            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from preferences-contacts-list (first contacts step) to preferences-delivery-window
        if (
          step?.target === '[data-tour="preferences-contacts-list"]' &&
          nextStep?.target === '[data-tour="preferences-delivery-window"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(() => {
            const el = document.querySelector(
              '[data-tour="preferences-delivery-window"]'
            );
            if (el) {
              el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from preferences-delivery-window to preferences-thresholds
        if (
          step?.target === '[data-tour="preferences-delivery-window"]' &&
          nextStep?.target === '[data-tour="preferences-thresholds"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(() => {
            const el = document.querySelector(
              '[data-tour="preferences-thresholds"]'
            );
            if (el) {
              el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from preferences-webhooks-list (first webhooks step) to preferences-contacts-add (last contacts step)
        if (
          step?.target === '[data-tour="preferences-webhooks-list"]' &&
          nextStep?.target === '[data-tour="preferences-contacts-add"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(() => {
            const el = document.querySelector(
              '[data-tour="preferences-contacts-add"]'
            );
            if (el) {
              el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from preferences-contact-groups-selector (first contact groups step) to preferences-webhooks-add (last webhooks step)
        if (
          step?.target ===
            '[data-tour="preferences-contact-groups-selector"]' &&
          nextStep?.target === '[data-tour="preferences-webhooks-add"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(() => {
            const el = document.querySelector(
              '[data-tour="preferences-webhooks-add"]'
            );
            if (el) {
              el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from usage-page to preferences-contact-groups-digest (last contact groups step)
        if (
          step?.target === '[data-tour="usage-page"]' &&
          nextStep?.target ===
            '[data-tour="preferences-contact-groups-digest"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(async () => {
            if (window.location.pathname !== '/preferences') {
              navigate('/preferences');
              await wait(500);
            }
            // Wait for contact groups digest to appear
            await waitForElement(
              '[data-tour="preferences-contact-groups-digest"]'
            );

            const selector = '[data-tour="preferences-contact-groups-digest"]';
            const isMobileNow =
              typeof window !== 'undefined' && window.innerWidth < 768;
            if (isMobileNow) {
              // Use the same helper as STEP_BEFORE for consistent placement on mobile
              scrollTargetWithTooltipSpaceMobile(selector, { delay: 0 });
              setTimeout(() => {
                setStepIndex(nextIndex);
                setIsRunning(true);
              }, 800);
              return;
            }
            const el = document.querySelector(selector);
            if (el) {
              el.scrollIntoView({ behavior: 'smooth', block: 'center' });
              setTimeout(() => {
                window.dispatchEvent(new Event('resize'));
                setTimeout(
                  () => window.dispatchEvent(new Event('resize')),
                  200
                );
                setStepIndex(nextIndex);
                setIsRunning(true);
              }, 500);
              return;
            }

            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: If going BACK from usage-nav to preferences-contact-groups-digest (last contact groups step)
        if (
          step?.target === '[data-tour="usage-nav"]' &&
          nextStep?.target ===
            '[data-tour="preferences-contact-groups-digest"]' &&
          action === ACTIONS.PREV
        ) {
          setIsRunning(false);
          setTimeout(async () => {
            if (window.location.pathname !== '/preferences') {
              navigate('/preferences');
              await wait(500);
            }
            // Wait for contact groups digest to appear
            await waitForElement(
              '[data-tour="preferences-contact-groups-digest"]'
            );

            const selector = '[data-tour="preferences-contact-groups-digest"]';
            const isMobileNow =
              typeof window !== 'undefined' && window.innerWidth < 768;
            if (isMobileNow) {
              // Use the same helper as STEP_BEFORE for consistent placement on mobile
              scrollTargetWithTooltipSpaceMobile(selector, { delay: 0 });
              setTimeout(() => {
                setStepIndex(nextIndex);
                setIsRunning(true);
              }, 800);
              return;
            }
            const el = document.querySelector(selector);
            if (el) {
              el.scrollIntoView({ behavior: 'smooth', block: 'center' });
              setTimeout(() => {
                window.dispatchEvent(new Event('resize'));
                setTimeout(
                  () => window.dispatchEvent(new Event('resize')),
                  200
                );
                setStepIndex(nextIndex);
                setIsRunning(true);
              }, 500);
              return;
            }

            setStepIndex(nextIndex);
            setIsRunning(true);
          }, 100);
          return;
        }

        // Special case: after the user-menu step, ensure menu is open for preferences-nav
        if (
          step?.target === '[data-tour="user-menu"]' &&
          nextStep?.target &&
          nextStep.target.includes('preferences-nav')
        ) {
          // Menu should already be open from STEP_BEFORE, but ensure it stays open
          setTimeout(() => {
            const menuButton = document.querySelector(
              '[data-tour="user-menu"]'
            );
            if (menuButton) {
              const isExpanded =
                menuButton.getAttribute('aria-expanded') === 'true';
              if (!isExpanded) {
                menuButton.click();
              }
            }
          }, 50);
        }

        // Special case: after the preferences-nav step, navigate to preferences
        if (
          step?.target &&
          step.target.includes('preferences-nav') &&
          nextStep?.target === '[data-tour="preferences-page"]'
        ) {
          setIsRunning(false); // pause tour during navigation

          // Release menu lock before navigation
          window.dispatchEvent(
            new CustomEvent('tt:tour-menu-state', {
              detail: { isActive: false, keepMenuOpen: false },
            })
          );

          // Click the preferences menu item to navigate
          setTimeout(async () => {
            // Use the actual target selector from the step
            const preferencesItem = document.querySelector(step.target);
            if (preferencesItem) {
              preferencesItem.click();
              // Wait a bit for navigation to start
              await wait(200);
            } else if (window.location.pathname !== '/preferences') {
              navigate('/preferences');
            }

            // Wait for the preferences page root element to be fully mounted
            const found = await waitForElement(nextStep.target, {
              timeout: 8000,
              interval: 150,
            });

            if (found) {
              // Additional wait to ensure React has fully rendered the component
              await wait(300);
              setStepIndex(nextIndex);
              setIsRunning(true); // resume tour at next step
            } else {
              // If we still didn't find it, continue anyway after a delay
              await wait(500);
              setStepIndex(nextIndex);
              setIsRunning(true);
            }
          }, 100);

          trackEvent('product_tour_step', {
            tour_type: tourType,
            step_index: nextIndex,
            step_total: activeSteps.length,
            action: action === ACTIONS.PREV ? 'back' : 'next',
          });
          return;
        }

        // Special case: after preferences-contact-groups-digest (last contact groups step), navigate to usage page (on mobile, usage-nav is skipped)
        if (
          step?.target === '[data-tour="preferences-contact-groups-digest"]' &&
          nextStep?.target === '[data-tour="usage-page"]'
        ) {
          setIsRunning(false); // pause tour during navigation

          setTimeout(async () => {
            if (window.location.pathname !== '/usage') {
              navigate('/usage');
            }

            // Wait for the usage page root element to be fully mounted
            const found = await waitForElement(nextStep.target, {
              timeout: 8000,
              interval: 150,
            });

            if (found) {
              // Additional wait to ensure React has fully rendered the component
              await wait(300);
              setStepIndex(nextIndex);
              setIsRunning(true); // resume tour at next step
            } else {
              // If we still didn't find it, continue anyway
              await wait(500);
              setStepIndex(nextIndex);
              setIsRunning(true);
            }
          }, 100);

          trackEvent('product_tour_step', {
            tour_type: tourType,
            step_index: nextIndex,
            step_total: activeSteps.length,
            action: action === ACTIONS.PREV ? 'back' : 'next',
          });
          return;
        }

        // Special case: after the usage-nav step, navigate to usage
        if (
          step?.target === '[data-tour="usage-nav"]' &&
          nextStep?.target === '[data-tour="usage-page"]'
        ) {
          setIsRunning(false); // pause tour during navigation

          setTimeout(async () => {
            if (window.location.pathname !== '/usage') {
              navigate('/usage');
            }

            // Wait for the usage page root element to be fully mounted
            const found = await waitForElement(nextStep.target, {
              timeout: 8000,
              interval: 150,
            });

            if (found) {
              // Additional wait to ensure React has fully rendered the component
              await wait(300);
              setStepIndex(nextIndex);
              setIsRunning(true); // resume tour at next step
            } else {
              // If we still didn't find it, continue anyway
              await wait(500);
              setStepIndex(nextIndex);
              setIsRunning(true);
            }
          }, 100);

          trackEvent('product_tour_step', {
            tour_type: tourType,
            step_index: nextIndex,
            step_total: activeSteps.length,
            action: action === ACTIONS.PREV ? 'back' : 'next',
          });
          return;
        }

        // Special case: after usage-alert-queue step, navigate back to dashboard and open drawer for docs-nav (mobile)
        if (
          step?.target === '[data-tour="usage-alert-queue"]' &&
          nextStep?.target &&
          (nextStep.target === '[data-tour="docs-nav"]' ||
            nextStep.target.includes('mobile-docs-nav'))
        ) {
          const isMobileNow =
            typeof window !== 'undefined' && window.innerWidth < 768;

          if (isMobileNow) {
            setIsRunning(false); // pause tour during navigation

            setTimeout(async () => {
              // Navigate back to dashboard if not already there
              if (
                window.location.pathname !== '/dashboard' &&
                window.location.pathname !== '/'
              ) {
                navigate('/dashboard');
                await wait(500); // Wait for navigation
              }

              // Open mobile drawer
              const menuButton = document.querySelector(
                '[data-tour="mobile-menu-button"]'
              );
              if (menuButton) {
                const drawer = document.querySelector(
                  '[data-tour="mobile-drawer"]'
                );
                const drawerVisible =
                  drawer && window.getComputedStyle(drawer).display !== 'none';

                if (!drawer || !drawerVisible) {
                  menuButton.click();
                  await wait(600); // Wait for drawer animation
                }
              }

              // Wait for the docs-nav element to be visible
              const targetSelector = nextStep.target.includes('mobile-docs-nav')
                ? nextStep.target
                : '[data-tour="mobile-docs-nav"]';

              const found = await waitForElement(targetSelector, {
                timeout: 3000,
                interval: 100,
              });

              if (found) {
                await wait(300); // Additional wait for React to render
                setStepIndex(nextIndex);
                setIsRunning(true);
              } else {
                // If we still didn't find it, continue anyway
                await wait(500);
                setStepIndex(nextIndex);
                setIsRunning(true);
              }
            }, 100);

            trackEvent('product_tour_step', {
              tour_type: tourType,
              step_index: nextIndex,
              step_total: activeSteps.length,
              action: action === ACTIONS.PREV ? 'back' : 'next',
            });
            return;
          }
        }

        // Default STEP_AFTER behaviour (no navigation)
        if (nextIndex >= 0 && nextIndex < activeSteps.length) {
          setIsRunning(true);
          setStepIndex(nextIndex);
        } else if (nextIndex >= activeSteps.length) {
          // Reached the end, finish the tour
          setIsRunning(false);
          setStepIndex(activeSteps.length - 1);
        } else {
          // Invalid index, stay on current step
          setStepIndex(index);
        }

        trackEvent('product_tour_step', {
          tour_type: tourType,
          step_index:
            nextIndex >= 0 && nextIndex < activeSteps.length
              ? nextIndex
              : index,
          step_total: activeSteps.length,
          action: action === ACTIONS.PREV ? 'back' : 'next',
        });
      }
    },
    [
      tourType,
      activeSteps,
      onTourComplete,
      navigate,
      waitForElement,
      ensureMobileDrawerClosed,
      closeMobileNav,
      wait,
      scrollTargetWithTooltipSpaceMobile,
    ]
  );

  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const joyrideStyles = useMemo(
    () => ({
      options: {
        primaryColor,
        textColor,
        backgroundColor: tooltipBg,
        overlayColor:
          colorMode === 'dark' ? 'rgba(0,0,0,0.7)' : 'rgba(0,0,0,0.5)',
        arrowColor: tooltipBg,
        zIndex: 10000,
      },
      overlay: {
        zIndex: 10000,
      },
      spotlight: {
        zIndex: 10650,
      },
      tooltip: {
        borderRadius: 8,
        border: `1px solid ${tooltipBorder}`,
        zIndex: 10700,
      },
      tooltipContainer: {
        zIndex: 10700,
      },
      tooltipContent: {
        zIndex: 10700,
      },
      buttonNext: {
        backgroundColor: buttonBg,
        color: '#fff',
        borderRadius: 6,
        padding: '8px 16px',
        fontSize: 14,
        fontWeight: 500,
        border: 'none',
        cursor: 'pointer',
        zIndex: 10701,
      },
      buttonBack: {
        color: textColor,
        marginRight: 10,
        fontSize: 14,
        zIndex: 10701,
      },
      buttonSkip: {
        color: textColor,
        fontSize: 14,
        zIndex: 10701,
      },
      beacon: {
        inner: {
          backgroundColor: primaryColor,
        },
        outer: {
          borderColor: primaryColor,
        },
      },
    }),
    [primaryColor, textColor, tooltipBg, tooltipBorder, buttonBg, colorMode]
  );

  if (activeSteps.length === 0) return null;

  return (
    <Joyride
      steps={activeSteps}
      run={isRunning}
      stepIndex={stepIndex}
      continuous
      showProgress
      showSkipButton
      styles={joyrideStyles}
      callback={handleJoyrideCallback}
      scrollOffset={120}
      disableOverlayClose
      disableCloseOnEsc
      floaterProps={{
        disableAnimation: !!prefersReducedMotion,
        // Better positioning on mobile
        styles: {
          floater: {
            filter: 'none',
            zIndex: 10700,
          },
        },
      }}
      scrollToFirstStep
      disableScrolling={false}
      hideCloseButton={true}
      disableScrollParentFix={true}
      locale={{
        back: 'Back',
        close: 'Close',
        last: 'Finish',
        next: 'Next',
        skip: 'Skip tour',
      }}
      spotlightPadding={6}
      tooltipComponent={props => (
        <CustomTooltip
          {...props}
          isLastStep={stepIndex === activeSteps.length - 1}
        />
      )}
    />
  );
}
