import { Button, Box, Tooltip, useColorModeValue } from '@chakra-ui/react';
import { FaWhatsapp } from 'react-icons/fa';

export default function TestWhatsappButton({
  onClick,
  isLoading = false,
  isDisabled = false,
  cooldownUntil = 0,
  label = 'Test WhatsApp Message',
  ...buttonProps
}) {
  const now = Date.now();
  const onCooldown = cooldownUntil > now;
  const cooldownSecs = onCooldown ? Math.ceil((cooldownUntil - now) / 1000) : 0;
  const tooltip = onCooldown
    ? `Wait ${cooldownSecs}s before sending another test`
    : 'Send test WhatsApp message';
  const bg = useColorModeValue('#25D366', '#14532d');
  const hoverBg = useColorModeValue('#20BD5A', '#166534');
  const activeBg = useColorModeValue('#1DA851', '#15803d');
  const color = useColorModeValue('white', '#dcfce7');
  const disabledBg = useColorModeValue('gray.400', 'gray.600');
  const disabledColor = useColorModeValue('white', 'gray.300');
  const borderColor = useColorModeValue(
    'transparent',
    'rgba(74, 222, 128, 0.22)'
  );

  return (
    <Tooltip label={tooltip} hasArrow openDelay={300} placement='top'>
      <Box as='span' display='inline-block'>
        <Button
        size='sm'
        h='30px'
        minH='30px'
        px={4}
        fontSize='sm'
        lineHeight='1.2'
        fontWeight='semibold'
        leftIcon={<FaWhatsapp size={14} />}
        bg={bg}
        color={color}
        borderRadius='md'
        borderWidth='1px'
        borderColor={borderColor}
        isLoading={isLoading}
        isDisabled={isDisabled || onCooldown}
        onClick={onClick}
        alignSelf='flex-start'
        whiteSpace='nowrap'
        _hover={{ bg: hoverBg }}
        _active={{ bg: activeBg }}
        _disabled={{
          bg: disabledBg,
          color: disabledColor,
          cursor: 'not-allowed',
          _hover: { bg: disabledBg },
        }}
        {...buttonProps}
      >
        {onCooldown ? `${cooldownSecs}s` : label}
      </Button>
      </Box>
    </Tooltip>
  );
}
