import {
  HStack,
  IconButton,
  Tooltip,
  useClipboard,
  useColorModeValue,
} from '@chakra-ui/react';
import { FiLink } from 'react-icons/fi';
import { FaXTwitter, FaFacebook, FaLinkedin } from 'react-icons/fa6';
import { showSuccess } from '../utils/toast.js';

export default function ShareButtons({ url, title }) {
  const { onCopy } = useClipboard(url);
  const iconColor = useColorModeValue('gray.600', 'gray.400');

  const handleCopyLink = () => {
    onCopy();
    showSuccess('Link copied to clipboard!');
  };

  const shareOnTwitter = () => {
    window.open(
      `https://twitter.com/intent/tweet?text=${encodeURIComponent(title)}&url=${encodeURIComponent(url)}`,
      '_blank'
    );
  };

  const shareOnFacebook = () => {
    window.open(
      `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}`,
      '_blank'
    );
  };

  const shareOnLinkedIn = () => {
    window.open(
      `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(url)}`,
      '_blank'
    );
  };

  return (
    <HStack spacing={1}>
      <Tooltip label='Copy link' placement='top'>
        <IconButton
          aria-label='Copy link'
          icon={<FiLink />}
          size='xs'
          variant='ghost'
          color={iconColor}
          onClick={handleCopyLink}
        />
      </Tooltip>
      <Tooltip label='Share on X' placement='top'>
        <IconButton
          aria-label='Share on X'
          icon={<FaXTwitter />}
          size='xs'
          variant='ghost'
          color={iconColor}
          onClick={shareOnTwitter}
        />
      </Tooltip>
      <Tooltip label='Share on Facebook' placement='top'>
        <IconButton
          aria-label='Share on Facebook'
          icon={<FaFacebook />}
          size='xs'
          variant='ghost'
          color={iconColor}
          onClick={shareOnFacebook}
        />
      </Tooltip>
      <Tooltip label='Share on LinkedIn' placement='top'>
        <IconButton
          aria-label='Share on LinkedIn'
          icon={<FaLinkedin />}
          size='xs'
          variant='ghost'
          color={iconColor}
          onClick={shareOnLinkedIn}
        />
      </Tooltip>
    </HStack>
  );
}
