const { map } = require('lodash/fp');

const {
  logging: { getLogger },
  errors: { parseErrorToReadableJson }
} = require('polarity-integration-utils');

const { requestsInParallel } = require('../request');

const getSearchResults = async (entities, options) => {
  const Logger = getLogger();

  try {
    const searchRequests = map(
      (entity) => ({
        resultId: entity.value,
        route: 'search/',
        qs: {
          aql: entity.types.includes('email')
            ? `in:users ${entity.value}`
            : entity.types.includes('cve')
            ? `in:vulnerabilities ${entity.value}`
            : entity.value,
          includeSample: true,
          includeTotal: true
        },
        options
      }),
      entities
    );

    const searchResults = await requestsInParallel(searchRequests, 'body.data.results');

    return searchResults;
  } catch (error) {
    const err = parseErrorToReadableJson(error);

    Logger.error(
      {
        formattedError: err,
        error
      },
      'Getting Search Results Failed'
    );

    throw error;
  }
};

module.exports = getSearchResults;
