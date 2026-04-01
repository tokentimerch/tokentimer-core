import { Image, useColorModeValue } from '@chakra-ui/react';

export default function AppIcon({ size = 75, width, height, ...props }) {
  const filter = useColorModeValue('none', 'invert(1)');
  return (
    <Image
      src='/Branding/app-icon.svg'
      alt='TokenTimer app icon'
      width={width ?? size}
      height={height ?? size}
      objectFit='contain'
      display='block'
      filter={filter}
      {...props}
    />
  );
}
