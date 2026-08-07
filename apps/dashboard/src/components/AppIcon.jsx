import { Image, useColorModeValue } from '@chakra-ui/react';
import { getAppIconPath } from '../utils/logoUtils.js';

export default function AppIcon({ size = 75, width, height, ...props }) {
  const filter = useColorModeValue('none', 'invert(1)');
  return (
    <Image
      src={getAppIconPath()}
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
