const { map, get, size, some, filter, flow, mean, round } = require('lodash/fp');
const { getResultForThisEntity } = require('./dataTransformations');

const assembleLookupResults = (entities, searchResults, options) =>
  map((entity) => {
    const searchResult = getResultForThisEntity(entity, searchResults);

    const lookupResult = {
      entity,
      data: size(searchResult)
        ? {
            summary: createSummaryTags(searchResult, entity),
            details: { searchResult }
          }
        : null
    };

    return lookupResult;
  }, entities);

const createSummaryTags = (searchResult, entity) => {
  const sizeTag = size(searchResult)
    ? entity.types.includes('email')
      ? `Users: ${size(searchResult)}`
      : entity.types.includes('cve')
      ? `Vulns: ${size(searchResult)}`
      : `Devices: ${size(searchResult)}`
    : [];

  const cvssScoreTag =
    size(searchResult) && some('cvssScore', searchResult)
      ? `${size(filter('cvssScore', searchResult)) > 1 ? 'Avg ' : ''}CVSS Score: ${flow(
          map('cvssScore'),
          mean,
          round
        )(searchResult)}`
      : [];

  const riskLevelTag =
    size(searchResult) && some('riskLevel', searchResult)
      ? `${size(filter('riskLevel', searchResult)) > 1 ? 'Avg ' : ''}Risk Score: ${flow(
          map('riskLevel'),
          mean,
          round
        )(searchResult)}`
      : [];
  return [].concat(sizeTag).concat(cvssScoreTag).concat(riskLevelTag); 
};

module.exports = assembleLookupResults;
