import { Fragment } from 'react';
import {
  Badge,
  Box,
  Button,
  Flex,
  Grid,
  GridItem,
  HStack,
  Heading,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Text,
} from '@chakra-ui/react';
import {
  DASHBOARD_MODAL_HEADING_FONT,
  DashboardModalFrame,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { getColorFromString } from '../../styles/colors.js';

function fileModeLabel(value) {
  if (value === null || value === undefined) return null;
  return `0${Number(value).toString(8)}`;
}

function boolLabel(value) {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return null;
}

/**
 * Full read-only detail view of a renewal profile's stored execution
 * contract, i.e. everything the panel's table can't show without becoming
 * unreadable: CA endpoint, account/EAB refs, ACME command, DNS-01
 * provider/zone, every deployment target's paths and ownership, and the
 * post-renewal verification check. Nothing here is editable, mirroring the
 * server: these fields fixed themselves the moment the issuance that
 * produced this profile succeeded, and changing them means issuing again.
 *
 * Styled to match TokenDetailModal's field-box grid so a profile's details
 * read like every other asset's details in this dashboard.
 */
export default function RenewalProfileDetailsModal({
  isOpen,
  onClose,
  profile,
}) {
  const {
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    primaryButtonProps,
    tokens,
  } = useDashboardModalProps();
  const fieldBg = tokens.fieldBg;
  const borderColor = tokens.border;
  const textColor = tokens.text;
  const labelColor = tokens.muted;
  const subtleTextColor = tokens.subtleText;
  const sectionAccent = tokens.sectionAccent;

  if (!profile) return null;

  const renewal = profile.renewalProfile || {};
  const sanPolicy = renewal.sanPolicy || {};
  const sans = Array.isArray(sanPolicy.sans) ? sanPolicy.sans : [];
  const targets = Array.isArray(renewal.deploymentTargets)
    ? renewal.deploymentTargets
    : renewal.target
      ? [renewal.target]
      : [];

  const renderFieldShell = (label, children, colSpan = { base: 1, md: 1 }) => (
    <GridItem colSpan={colSpan}>
      <Box
        bg={fieldBg}
        border='1px solid'
        borderColor={borderColor}
        borderRadius='12px'
        p={{ base: 3.5, md: 4 }}
        minH='72px'
      >
        <Text fontSize='sm' fontWeight='semibold' color={labelColor} mb={2}>
          {label}
        </Text>
        {children}
      </Box>
    </GridItem>
  );

  const renderValueText = (value, mono = false) => (
    <Text
      fontSize={{ base: 'sm', md: 'md' }}
      fontWeight='semibold'
      color={textColor}
      lineHeight='1.45'
      wordBreak='break-word'
      fontFamily={mono ? 'mono' : undefined}
    >
      {value}
    </Text>
  );

  const renderField = (label, value, options = {}) => {
    if (value === null || value === undefined || value === '') return null;
    const { colSpan, mono } = options;
    return renderFieldShell(label, renderValueText(value, mono), colSpan);
  };

  const renderSectionTitle = (label, withDivider = true) => (
    <GridItem colSpan={{ base: 1, md: 2 }}>
      <Box
        borderTop={withDivider ? '1px solid' : '0'}
        borderColor={borderColor}
        pt={withDivider ? { base: 4, md: 5 } : 0}
        mt={withDivider ? { base: 1, md: 2 } : 0}
      >
        <HStack spacing={3}>
          <Box
            w='3px'
            h='18px'
            borderRadius='full'
            bg={sectionAccent}
            flexShrink={0}
          />
          <Text
            fontSize={{ base: 'md', md: 'lg' }}
            fontWeight='bold'
            fontFamily={DASHBOARD_MODAL_HEADING_FONT}
            color={textColor}
          >
            {label}
          </Text>
        </HStack>
      </Box>
    </GridItem>
  );

  const renderSansField = () => {
    if (sans.length === 0) return null;
    return renderFieldShell(
      'SANs',
      <HStack spacing={2} flexWrap='wrap'>
        {sans.map(san => (
          <Badge
            key={san}
            colorScheme={getColorFromString(san)}
            variant='subtle'
          >
            {san}
          </Badge>
        ))}
      </HStack>,
      { base: 1, md: 2 }
    );
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size='xl'
      scrollBehavior='inside'
      isCentered
      motionPreset='none'
    >
      <ModalOverlay />
      <DashboardModalFrame maxW={{ base: 'calc(100vw - 24px)', md: '760px' }}>
        <ModalHeader {...headerProps}>
          <Flex
            align={{ base: 'flex-start', md: 'center' }}
            justify='space-between'
            gap={4}
            direction={{ base: 'column', sm: 'row' }}
          >
            <Box minW={0}>
              <Heading
                size={{ base: 'md', md: 'lg' }}
                color={textColor}
                fontFamily={DASHBOARD_MODAL_HEADING_FONT}
                noOfLines={2}
              >
                {profile.name}
              </Heading>
              <Text
                fontSize={{ base: 'sm', md: 'md' }}
                color={subtleTextColor}
                mt={2}
                noOfLines={2}
              >
                Renewal profile
              </Text>
            </Box>
            {profile.derived ? (
              <Badge
                colorScheme='blue'
                variant='subtle'
                fontSize='xs'
                borderRadius='8px'
                px={3}
                py={1.5}
                flexShrink={0}
              >
                Derived
              </Badge>
            ) : null}
          </Flex>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />

        <ModalBody {...bodyProps}>
          <Grid
            templateColumns={{ base: 'minmax(0, 1fr)', md: 'repeat(2, 1fr)' }}
            gap={{ base: 3, md: 4 }}
          >
            {renderSectionTitle('Overview', false)}
            {renderField('Certificates using it', profile.certificateCount)}
            {renderField('Auto-renew', boolLabel(profile.autoRenewEnabled))}
            {renderField(
              'Lead time',
              profile.renewBeforeDays == null
                ? 'Deployment default'
                : `${profile.renewBeforeDays} days`
            )}
            {renderField('Status', profile.status)}
            {renderField('Description', profile.description, {
              colSpan: { base: 1, md: 2 },
            })}

            {renderSectionTitle('Certificate')}
            {renderField(
              'Key',
              renewal.keyAlgorithm
                ? `${String(renewal.keyAlgorithm).toUpperCase()} ${renewal.keySize || ''}`.trim()
                : null
            )}
            {renderField(
              'Rotate key on renew',
              boolLabel(renewal.keyRotationPolicy?.rotateOnRenew)
            )}
            {renderField('Preferred chain', renewal.preferredChain)}
            {renderField('SAN policy', sanPolicy.mode)}
            {renderField(
              'Allow wildcard SANs',
              boolLabel(sanPolicy.allowWildcards)
            )}
            {renderSansField()}

            {renderSectionTitle('CA & ACME')}
            {renderField('CA endpoint', renewal.ca?.endpoint, {
              colSpan: { base: 1, md: 2 },
              mono: true,
            })}
            {renderField('Account reference', renewal.ca?.accountRef, {
              mono: true,
            })}
            {renderField('EAB reference', renewal.ca?.eabRef, { mono: true })}
            {renderField('ACME client', renewal.acme?.kind)}
            {renderField('Command profile', renewal.acme?.commandRef, {
              mono: true,
            })}

            {renderSectionTitle('DNS-01 challenge')}
            {renderField('Provider', renewal.dns?.provider)}
            {renderField('Zone', renewal.dns?.zone, { mono: true })}

            {renderSectionTitle(
              `Deployment target${targets.length > 1 ? 's' : ''}`
            )}
            {targets.length === 0
              ? renderField('Deployment target', 'None recorded')
              : targets.map((target, index) => (
                  <Fragment key={`${target.reference || 'target'}-${index}`}>
                    {targets.length > 1
                      ? renderSectionTitle(`Target ${index + 1}`, index > 0)
                      : null}
                    {renderField('Type', target.type)}
                    {renderField('Reference', target.reference, {
                      mono: true,
                    })}
                    {renderField('Certificate path', target.certPath, {
                      mono: true,
                    })}
                    {renderField('Key path', target.keyPath, { mono: true })}
                    {renderField('Chain path', target.chainPath, {
                      mono: true,
                    })}
                    {renderField('Reload service', target.reloadService, {
                      mono: true,
                    })}
                    {renderField('Owner', target.owner, { mono: true })}
                    {renderField('Group', target.group, { mono: true })}
                    {renderField(
                      'Certificate file mode',
                      fileModeLabel(target.certMode),
                      { mono: true }
                    )}
                    {renderField(
                      'Key file mode',
                      fileModeLabel(target.keyMode),
                      { mono: true }
                    )}
                    {renderField(
                      'Chain file mode',
                      fileModeLabel(target.chainMode),
                      { mono: true }
                    )}
                    {renderField('Backup directory', target.backupDir, {
                      mono: true,
                    })}
                    {renderField(
                      'Backup retention',
                      target.backupRetentionCount == null
                        ? null
                        : `${target.backupRetentionCount} ${target.backupRetentionCount === 1 ? 'copy' : 'copies'}`
                    )}
                  </Fragment>
                ))}

            {renderSectionTitle('Post-renewal verification')}
            {renderField('Host', renewal.verification?.host, { mono: true })}
            {renderField('Port', renewal.verification?.port)}
            {renderField(
              'Require match',
              boolLabel(renewal.verification?.requireMatch)
            )}
          </Grid>
        </ModalBody>

        <ModalFooter {...footerProps}>
          <Flex
            w='100%'
            align='center'
            justify='space-between'
            gap={3}
            direction={{ base: 'column', md: 'row' }}
          >
            <Text fontSize='sm' color={labelColor}>
              Deployment details are read-only; changing them means issuing
              again.
            </Text>
            <Button
              onClick={onClose}
              minW={{ base: '100%', sm: '104px' }}
              {...primaryButtonProps}
            >
              Close
            </Button>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
