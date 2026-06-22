import { useCallback, useEffect, useState, useRef } from 'react';
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
  const [isTooltipOpen, setIsTooltipOpen] = useState(false);
  const [isPointerInside, setIsPointerInside] = useState(false);
  const textRef = useRef(null);
  const openTimerRef = useRef(null);
  const scrollBlockTimerRef = useRef(null);
  const isScrollBlockedRef = useRef(false);

  const clearOpenTimer = useCallback(() => {
    if (openTimerRef.current) {
      window.clearTimeout(openTimerRef.current);
      openTimerRef.current = null;
    }
  }, []);

  const closeTooltip = useCallback(() => {
    clearOpenTimer();
    setIsTooltipOpen(false);
  }, [clearOpenTimer]);

  const blockTooltipDuringScroll = useCallback(() => {
    isScrollBlockedRef.current = true;
    closeTooltip();

    if (scrollBlockTimerRef.current) {
      window.clearTimeout(scrollBlockTimerRef.current);
    }

    scrollBlockTimerRef.current = window.setTimeout(() => {
      isScrollBlockedRef.current = false;
      scrollBlockTimerRef.current = null;
    }, 180);
  }, [closeTooltip]);

  const scheduleTooltipOpen = useCallback(() => {
    if (!isTextTruncated || isScrollBlockedRef.current) return;
    clearOpenTimer();

    openTimerRef.current = window.setTimeout(() => {
      if (!isScrollBlockedRef.current) {
        setIsTooltipOpen(true);
      }
      openTimerRef.current = null;
    }, 300);
  }, [clearOpenTimer, isTextTruncated]);

  const handleTooltipEnter = useCallback(() => {
    setIsPointerInside(true);
    scheduleTooltipOpen();
  }, [scheduleTooltipOpen]);

  const handleTooltipLeave = useCallback(() => {
    setIsPointerInside(false);
    closeTooltip();
  }, [closeTooltip]);

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

  useEffect(() => {
    if (!isPointerInside && !isTooltipOpen) return undefined;

    window.addEventListener('wheel', blockTooltipDuringScroll, {
      capture: true,
      passive: true,
    });
    window.addEventListener('scroll', blockTooltipDuringScroll, true);

    return () => {
      window.removeEventListener('wheel', blockTooltipDuringScroll, {
        capture: true,
      });
      window.removeEventListener('scroll', blockTooltipDuringScroll, true);
    };
  }, [blockTooltipDuringScroll, isPointerInside, isTooltipOpen]);

  useEffect(
    () => () => {
      clearOpenTimer();
      if (scrollBlockTimerRef.current) {
        window.clearTimeout(scrollBlockTimerRef.current);
      }
    },
    [clearOpenTimer]
  );

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
      isOpen={isTooltipOpen}
      bg='gray.800'
      color='white'
      fontSize='sm'
      px={3}
      py={2}
      borderRadius='md'
      maxW='300px'
      whiteSpace='normal'
      wordBreak='break-word'
      shouldWrapChildren
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
        onMouseEnter={handleTooltipEnter}
        onMouseLeave={handleTooltipLeave}
        onFocus={handleTooltipEnter}
        onBlur={handleTooltipLeave}
        onWheelCapture={blockTooltipDuringScroll}
      >
        {text}
      </Text>
    </Tooltip>
  );
}
