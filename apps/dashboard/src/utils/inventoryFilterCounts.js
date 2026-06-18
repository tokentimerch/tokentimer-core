import {
  classifyExpiryBucket,
  computeDaysLeftUtc,
} from './expiryBuckets';

export function normInventoryValue(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

export function splitInventoryList(value) {
  return String(value || '')
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);
}

export function buildInventoryFilterContext({
  statusFilter = 'all',
  selectedCategoryValues = [],
  sectionParam = '__all__',
  search = '',
} = {}) {
  return {
    statusFilter: statusFilter || 'all',
    selectedCategoryValues: Array.isArray(selectedCategoryValues)
      ? selectedCategoryValues
      : [],
    sectionParam: sectionParam || '__all__',
    search: String(search || '').trim(),
  };
}

export function isAnyInventoryFilterActive(ctx) {
  return (
    ctx.statusFilter !== 'all' ||
    ctx.selectedCategoryValues.length > 0 ||
    ctx.sectionParam !== '__all__' ||
    Boolean(ctx.search)
  );
}

export function tokenMatchesInventorySearch(token, search) {
  if (!search) return true;
  const query = search.toLowerCase();
  const fields = [
    token.name,
    token.type,
    token.vendor,
    token.license_type,
    token.issuer,
    token.location,
    token.used_by,
    token.description,
    token.subject,
    token.serial_number,
    token.privileges,
  ];
  if (Array.isArray(token.domains)) fields.push(token.domains.join(', '));
  if (Array.isArray(token.section)) fields.push(token.section.join(', '));
  return fields.some(value =>
    value ? String(value).toLowerCase().includes(query) : false
  );
}

export function tokenMatchesInventoryStatus(token, statusFilter, getStatusKey) {
  if (!statusFilter || statusFilter === 'all') return true;
  const status = getStatusKey(token.expiresAt);
  return (
    statusFilter === status ||
    (statusFilter === 'due' && status === 'due-soon') ||
    (statusFilter === 'critical' &&
      (status === 'critical' || status === 'expired')) ||
    (statusFilter === 'healthy' && status === 'healthy')
  );
}

export function tokenMatchesInventoryCategory(token, selectedCategoryValues) {
  if (!selectedCategoryValues.length) return true;
  return selectedCategoryValues.includes(token.category);
}

export function tokenMatchesInventorySection(token, sectionParam) {
  if (!sectionParam || sectionParam === '__all__') return true;

  if (sectionParam === '__none__') {
    return (
      !token.section ||
      (Array.isArray(token.section) && token.section.length === 0) ||
      String(token.section).trim() === ''
    );
  }

  const wantedList = splitInventoryList(sectionParam).map(normInventoryValue);
  const tokenSections = Array.isArray(token.section)
    ? token.section.map(section => normInventoryValue(section))
    : [normInventoryValue(token.section)];

  return wantedList.some(wanted => tokenSections.includes(wanted));
}

export function tokenMatchesInventoryFilters(
  token,
  ctx,
  exclude = null,
  getStatusKey
) {
  if (
    exclude !== 'search' &&
    !tokenMatchesInventorySearch(token, ctx.search)
  ) {
    return false;
  }
  if (
    exclude !== 'status' &&
    !tokenMatchesInventoryStatus(token, ctx.statusFilter, getStatusKey)
  ) {
    return false;
  }
  if (
    exclude !== 'category' &&
    !tokenMatchesInventoryCategory(token, ctx.selectedCategoryValues)
  ) {
    return false;
  }
  if (
    exclude !== 'section' &&
    !tokenMatchesInventorySection(token, ctx.sectionParam)
  ) {
    return false;
  }
  return true;
}

export function filterTokensForInventoryCounts(
  tokens,
  ctx,
  exclude,
  getStatusKey
) {
  const source = Array.isArray(tokens) ? tokens.filter(Boolean) : [];
  return source.filter(token =>
    tokenMatchesInventoryFilters(token, ctx, exclude, getStatusKey)
  );
}

export function computeInventoryStatusMetrics(tokens) {
  const loadedTokens = Array.isArray(tokens) ? tokens.filter(Boolean) : [];

  let expiring30 = 0;
  let critical = 0;
  let expired = 0;
  let healthy = 0;

  for (const token of loadedTokens) {
    const bucket = classifyExpiryBucket(computeDaysLeftUtc(token.expiresAt));
    switch (bucket) {
      case 'expired':
        expired += 1;
        critical += 1;
        break;
      case 'expiring7':
        critical += 1;
        break;
      case 'expiring8To30':
        expiring30 += 1;
        break;
      case 'healthy':
        healthy += 1;
        break;
      default:
        break;
    }
  }

  return {
    total: loadedTokens.length,
    critical,
    expiring30,
    healthy,
    expired,
  };
}

function readFacetCategoryCount(facetSources, categoryValue, categoryCounts) {
  for (const facetSource of facetSources) {
    const match = (facetSource || []).find(
      row => String(row.category) === categoryValue
    );
    if (typeof match?.c === 'number') return match.c;
  }
  return typeof categoryCounts?.[categoryValue] === 'number'
    ? categoryCounts[categoryValue]
    : 0;
}

export function buildCategoryFilterOptions({
  tokenCategories,
  tokens,
  ctx,
  selectedCategoryValues,
  globalFacets,
  tokenFacets,
  categoryCounts,
  getStatusKey,
}) {
  const deriveFromTokens = isAnyInventoryFilterActive(ctx);
  const facetSources = [
    globalFacets?.category,
    tokenFacets?.category,
  ];

  return tokenCategories
    .map(category => ({
      ...category,
      count: deriveFromTokens
        ? filterTokensForInventoryCounts(
            tokens,
            ctx,
            'category',
            getStatusKey
          ).filter(token => token.category === category.value).length
        : readFacetCategoryCount(facetSources, category.value, categoryCounts),
      active: selectedCategoryValues.includes(category.value),
    }))
    .filter(
      category =>
        !deriveFromTokens ||
        category.count > 0 ||
        selectedCategoryValues.includes(category.value)
    );
}

export function getCategorySelectionCount({
  categoryValue,
  tokens,
  ctx,
  globalFacets,
  tokenFacets,
  categoryCounts,
  getStatusKey,
}) {
  if (!categoryValue) return 0;

  const deriveFromTokens = isAnyInventoryFilterActive(ctx);
  const facetSources = [globalFacets?.category, tokenFacets?.category];

  if (deriveFromTokens) {
    return filterTokensForInventoryCounts(
      tokens,
      ctx,
      'category',
      getStatusKey
    ).filter(token => token.category === categoryValue).length;
  }

  return readFacetCategoryCount(facetSources, categoryValue, categoryCounts);
}

export function pruneSelectedCategories({
  selectedCategoryValues,
  tokens,
  ctx,
  globalFacets,
  tokenFacets,
  categoryCounts,
  getStatusKey,
}) {
  const selected = Array.isArray(selectedCategoryValues)
    ? selectedCategoryValues.filter(Boolean)
    : [];
  if (selected.length === 0) return selected;

  return selected.filter(
    categoryValue =>
      getCategorySelectionCount({
        categoryValue,
        tokens,
        ctx,
        globalFacets,
        tokenFacets,
        categoryCounts,
        getStatusKey,
      }) > 0
  );
}

function collectSectionLabels(token) {
  return Array.isArray(token.section)
    ? token.section.flatMap(section => splitInventoryList(section))
    : splitInventoryList(token.section);
}

function buildSectionCountMap(tokens) {
  const sectionCounts = {};
  let noneCount = 0;

  tokens.forEach(token => {
    const labels = collectSectionLabels(token);
    if (labels.length === 0) {
      noneCount += 1;
      return;
    }

    const uniqueKeys = [
      ...new Set(labels.map(label => normInventoryValue(label))),
    ];
    uniqueKeys.forEach(key => {
      sectionCounts[key] = (sectionCounts[key] || 0) + 1;
    });
  });

  return {
    sectionCounts,
    noneCount,
    total: tokens.length,
  };
}

function readFacetSectionCounts(facetSource, categoryCounts) {
  const rawMap = {};

  (facetSource || []).forEach(row => {
    const labels = splitInventoryList(row.section);
    if (labels.length === 0) {
      const key = '';
      if (!rawMap[key]) rawMap[key] = { name: '', count: 0 };
      rawMap[key].count += row.c || 0;
      return;
    }

    labels.forEach(label => {
      const key = normInventoryValue(label);
      if (!rawMap[key]) rawMap[key] = { name: label, count: 0 };
      rawMap[key].count = Math.max(rawMap[key].count, row.c || 0);
    });
  });

  const allKnownSections = {};
  (facetSource || []).forEach(row => {
    splitInventoryList(row.section).forEach(label => {
      const key = normInventoryValue(label);
      if (!allKnownSections[key]) allKnownSections[key] = { name: label };
    });
  });

  const mergedSections = Object.values(allKnownSections).map(section => ({
    name: section.name,
    count: rawMap[normInventoryValue(section.name)]?.count || 0,
  }));

  const allCount = Object.values(categoryCounts || {}).reduce(
    (sum, count) => sum + (count || 0),
    0
  );

  return {
    mergedSections,
    allCount,
    noneCount: rawMap['']?.count || 0,
    rawMap,
  };
}

export function buildSectionFilterOptions({
  tokens,
  ctx,
  facetSource,
  categoryCounts,
  getSectionColorScheme,
  getStatusKey,
}) {
  const deriveFromTokens = isAnyInventoryFilterActive(ctx);
  const facetData = readFacetSectionCounts(facetSource, categoryCounts);
  const tokensForCounts = deriveFromTokens
    ? filterTokensForInventoryCounts(tokens, ctx, 'section', getStatusKey)
    : [];
  const tokenCounts = deriveFromTokens
    ? buildSectionCountMap(tokensForCounts)
    : null;

  const knownSections = new Map();
  facetData.mergedSections.forEach(section => {
    knownSections.set(normInventoryValue(section.name), section.name);
  });

  if (deriveFromTokens) {
    Object.keys(tokenCounts.sectionCounts).forEach(key => {
      if (!knownSections.has(key)) {
        knownSections.set(key, key);
      }
    });
  }

  const mergedSections = Array.from(knownSections.entries()).map(
    ([key, name]) => ({
      name,
      count: deriveFromTokens
        ? tokenCounts.sectionCounts[key] || 0
        : facetData.rawMap[key]?.count || 0,
    })
  );

  const allCount = deriveFromTokens ? tokenCounts.total : facetData.allCount;
  const noneCount = deriveFromTokens
    ? tokenCounts.noneCount
    : facetData.noneCount;

  const currentSection = ctx.sectionParam || '__all__';
  const activeNames =
    currentSection === '__all__' || currentSection === '__none__'
      ? []
      : splitInventoryList(currentSection);

  const toSectionOption = section => ({
    name: section.name,
    label: section.name,
    count: section.count,
    scheme: getSectionColorScheme(section.name),
  });

  const included = new Set();
  const activeOptions = activeNames.map(name => {
    const key = normInventoryValue(name);
    const merged = mergedSections.find(
      section => normInventoryValue(section.name) === key
    );
    return toSectionOption(
      merged || {
        name,
        count: deriveFromTokens
          ? tokenCounts.sectionCounts[key] || 0
          : facetData.rawMap[key]?.count || 0,
      }
    );
  });
  activeOptions.forEach(option => included.add(normInventoryValue(option.name)));

  const nonZeroOptions = mergedSections
    .filter(
      section =>
        section.count > 0 && !included.has(normInventoryValue(section.name))
    )
    .sort(
      (left, right) =>
        right.count - left.count || left.name.localeCompare(right.name)
    )
    .map(toSectionOption);
  nonZeroOptions.forEach(option => included.add(normInventoryValue(option.name)));

  const zeroSections = deriveFromTokens
    ? []
    : mergedSections
        .filter(
          section =>
            section.count === 0 &&
            !included.has(normInventoryValue(section.name))
        )
        .sort((left, right) => left.name.localeCompare(right.name));

  const zeroOptions = zeroSections.slice(0, 5).map(toSectionOption);
  const moreZeros = zeroSections.length > 5;

  return [
    {
      name: '__all__',
      label: 'All sections',
      count: allCount,
      scheme: 'blue',
    },
    {
      name: '__none__',
      label: 'No section',
      count: noneCount,
      scheme: 'gray',
    },
    ...activeOptions,
    ...nonZeroOptions,
    ...zeroOptions,
    ...(moreZeros
      ? [
          {
            name: '__more__',
            label: 'More sections…',
            count: zeroSections.length - 5,
            scheme: 'gray',
          },
        ]
      : []),
  ];
}

export function getSectionSelectionCount({
  sectionParam,
  tokens,
  ctx,
  facetSource,
  categoryCounts,
  getStatusKey,
}) {
  const value = sectionParam || '__all__';
  if (value === '__all__') return null;

  const deriveFromTokens = isAnyInventoryFilterActive(ctx);
  const facetData = readFacetSectionCounts(facetSource, categoryCounts);

  if (value === '__none__') {
    if (deriveFromTokens) {
      return buildSectionCountMap(
        filterTokensForInventoryCounts(tokens, ctx, 'section', getStatusKey)
      ).noneCount;
    }
    return facetData.noneCount;
  }

  const activeNames = splitInventoryList(value);
  if (deriveFromTokens) {
    const tokenCounts = buildSectionCountMap(
      filterTokensForInventoryCounts(tokens, ctx, 'section', getStatusKey)
    );
    return activeNames.reduce(
      (sum, name) =>
        sum + (tokenCounts.sectionCounts[normInventoryValue(name)] || 0),
      0
    );
  }

  return activeNames.reduce(
    (sum, name) =>
      sum + (facetData.rawMap[normInventoryValue(name)]?.count || 0),
    0
  );
}

export function shouldClearSectionSelection(options) {
  const count = getSectionSelectionCount(options);
  return count !== null && count === 0;
}
