/**
 * @deprecated Use useArticleColors from '../hooks/useColors' instead
 * This file is kept for backward compatibility
 */
import { useArticleColors as useArticleColorsNew } from '../hooks/useColors';

export default function useArticleColors() {
  return useArticleColorsNew();
}
