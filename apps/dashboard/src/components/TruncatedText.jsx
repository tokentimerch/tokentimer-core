import { useEffect, useState, useRef } from 'react';
import { Text, Tooltip, useColorModeValue } from '@chakra-ui/react';

export default function TruncatedText({
  text,
  maxLines = 1,
  fontSize = 'sm',
  maxWidth = null,
}) {
  const truncatedTextColor = useColorModeValue('gray.700', 'gray.300');
  const emptyTextColor = useColorModeValue('gray.400', 'gray.500');
  const [isTextTruncated, setIsTextTruncated] = useState(false);
  const textRef = useRef(null);

  useEffect(() => {
    if (textRef.current && text) {
      const element = textRef.current;
      const isOverflowing =
        element.scrollHeight > element.clientHeight ||
        element.scrollWidth > element.clientWidth;
      setIsTextTruncated(isOverflowing);
    } else {
      setIsTextTruncated(false);
    }
  }, [text]);

  if (!text) {
    return (
      <Text fontSize={fontSize} color={emptyTextColor}>
        -
      </Text>
    );
  }

  return (
    <Tooltip
      label={text}
      placement='top'
      hasArrow
      isDisabled={!isTextTruncated}
      bg='gray.800'
      color='white'
      fontSize='sm'
      px={3}
      py={2}
      borderRadius='md'
      maxW='300px'
      whiteSpace='normal'
      wordBreak='break-word'
    >
      <Text
        ref={textRef}
        fontSize={fontSize}
        color={truncatedTextColor}
        noOfLines={maxLines}
        cursor={isTextTruncated ? 'help' : 'default'}
        maxW={maxWidth}
        wordBreak='break-word'
        overflow='hidden'
        textOverflow='ellipsis'
      >
        {text}
      </Text>
    </Tooltip>
  );
}
