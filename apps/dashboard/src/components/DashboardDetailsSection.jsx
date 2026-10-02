import { Children, cloneElement, isValidElement } from 'react';
import { Box, Grid, Heading, HStack, Icon, Text } from '@chakra-ui/react';
import { DASHBOARD_MODAL_HEADING_FONT } from './DashboardModalFrame.jsx';

export default function DashboardDetailsSection({
  title,
  description,
  children,
  mb = 6,
  columns = 1,
  enclosed = false,
  compactValues = false,
  contentBorder = true,
  propertyValueRows = false,
  icon: SectionIcon,
}) {
  const visibleChildren = Children.toArray(children).filter(Boolean);
  if (visibleChildren.length === 0) return null;
  const usesTwoColumns = columns === 2;
  const renderedChildren =
    compactValues || enclosed
      ? visibleChildren.map(child =>
          isValidElement(child)
            ? cloneElement(child, {
                compactValue: compactValues,
                tableStyle: enclosed,
                propertyValueStyle: propertyValueRows,
              })
            : child
        )
      : visibleChildren;

  const detailsGrid = (
    <Grid
      data-detail-columns={columns}
      data-section-enclosed={String(enclosed)}
      templateColumns='minmax(0, 1fr)'
      position='relative'
      mx={enclosed ? 3 : 0}
      border={contentBorder ? '1px solid' : 0}
      borderWidth={enclosed ? 0 : undefined}
      borderLeftWidth={enclosed ? 0 : undefined}
      borderRightWidth={enclosed ? 0 : undefined}
      borderColor='dashboard.modal.border'
      _before={
        usesTwoColumns
          ? {
              content: '""',
              display: { base: 'none', md: 'block' },
              position: 'absolute',
              top: propertyValueRows ? 2 : 0,
              bottom: propertyValueRows ? 2 : 0,
              left: '50%',
              width: '1px',
              bg: 'dashboard.modal.border',
              pointerEvents: 'none',
            }
          : undefined
      }
      sx={{
        '& > [data-detail-row]:last-of-type': { borderBottom: 0 },
        ...(usesTwoColumns
          ? {
              '@media screen and (min-width: 48em)': {
                gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                '& > [data-detail-row]:nth-of-type(odd)': {
                  paddingRight: enclosed ? '16px' : '20px',
                },
                '& > [data-detail-row]:nth-of-type(even)': {
                  paddingLeft: enclosed ? '16px' : '20px',
                },
                '& > [data-detail-row]:nth-last-of-type(-n + 2)': {
                  borderBottom: 0,
                },
              },
            }
          : {}),
      }}
    >
      {renderedChildren}
    </Grid>
  );

  if (enclosed) {
    return (
      <Box
        as='section'
        data-compact-section='true'
        mb={mb}
        minW={0}
        border='1px solid'
        borderColor='dashboard.modal.border'
        borderRadius='8px'
        overflow='hidden'
      >
        <HStack
          data-compact-section-heading
          mx={3}
          pt={2.5}
          pb={2}
          spacing={2}
          borderBottom='1px solid'
          borderColor='dashboard.modal.border'
        >
          {SectionIcon ? (
            <Icon
              as={SectionIcon}
              boxSize={4}
              flexShrink={0}
              color='dashboard.modal.muted'
              aria-hidden='true'
            />
          ) : null}
          <Box minW={0}>
            <Heading
              as='h3'
              fontFamily={DASHBOARD_MODAL_HEADING_FONT}
              fontSize='sm'
              fontWeight='bold'
              letterSpacing='0.01em'
            >
              {title}
            </Heading>
            {description ? (
              <Text mt={1} fontSize='xs' color='dashboard.modal.muted'>
                {description}
              </Text>
            ) : null}
          </Box>
        </HStack>
        {detailsGrid}
      </Box>
    );
  }

  return (
    <Box as='section' mb={mb} minW={0}>
      <Box mb={2}>
        <Heading
          as='h3'
          fontFamily={DASHBOARD_MODAL_HEADING_FONT}
          fontSize='sm'
          fontWeight='bold'
          letterSpacing='0.01em'
        >
          {title}
        </Heading>
        {description ? (
          <Text mt={1} fontSize='xs' color='dashboard.modal.muted'>
            {description}
          </Text>
        ) : null}
      </Box>
      {detailsGrid}
    </Box>
  );
}
