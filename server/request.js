const {
  map,
  get,
  getOr,
  filter,
  flow,
  negate,
  isEmpty,
  tail,
  first
} = require('lodash/fp');
const { parallelLimit } = require('async');

const {
  requests: { createRequestWithDefaults }
} = require('polarity-integration-utils');
const config = require('../config/config');
const { DateTime } = require('luxon');
const NodeCache = require('node-cache');
const tokenCache = new NodeCache();

const requestForAuth = createRequestWithDefaults({
  config,
  roundedSuccessStatusCodes: [200],
  requestOptionsToOmitFromLogsKeyPaths: [
    'headers.Authorization',
    'form.secret_key',
    'body.data.access_token'
  ],
  postprocessRequestFailure: (error) => {
    error.message = `Authentication Failed: Check Credentials and Try Again - (${error.status})`;

    throw error;
  }
});

const requestWithDefaults = createRequestWithDefaults({
  config,
  roundedSuccessStatusCodes: [200],
  requestOptionsToOmitFromLogsKeyPaths: ['headers.Authorization', 'form.secret_key'],
  preprocessRequestOptions: async ({ route, options, ...requestOptions }) => {
    const token = await getAuthToken(options);

    return {
      ...requestOptions,
      url: `${options.url}/api/v1/${route}`,
      headers: {
        Authorization: token
      },
      json: true
    };
  },
  postprocessRequestResponse: async (response, requestOptions) => {
    const nextPageNumber = get('body.data.next', response);
    if (nextPageNumber && get('body.data.results', response) <= 30) {
      const nextPageResults = get(
        'body.data.results',
        await requestWithDefaults({
          ...requestOptions,
          qs: { ...requestOptions.qs, from: nextPageNumber }
        })
      );

      response.body.data.results = [...response.body.data.results, ...nextPageResults];
    }

    return response;
  },
  postprocessRequestFailure: (error) => {
    const errorResponseBody = JSON.parse(error.description);
    error.message = `${error.message} - (${error.status})${
      errorResponseBody.message || errorResponseBody.error
        ? `| ${errorResponseBody.message || errorResponseBody.error}`
        : ''
    }`;

    throw error;
  }
});

const getAuthToken = async ({ url, secretKey }) => {
  const cachedToken = tokenCache.get(secretKey);
  if (cachedToken) return cachedToken;

  const { access_token, expiration_utc } = get(
    'body.data',
    await requestForAuth({
      method: 'POST',
      url: `${url}/api/v1/access_token/`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      form: { secret_key: secretKey },
      json: true
    })
  );

  const tokenResetSeconds =
    Math.abs(
      Math.round(
        DateTime.utc().diff(DateTime.fromISO(expiration_utc, { zone: 'utc' }), 'seconds')
          .seconds
      )
    ) - 10;

  tokenCache.set(secretKey, access_token, tokenResetSeconds);

  return access_token;
};

const createRequestsInParallel =
  (requestWithDefaults) =>
  async (
    requestsOptions,
    responseGetPath,
    limit = 10,
    onlyReturnPopulatedResults = true
  ) => {
    const unexecutedRequestFunctions = map(
      ({ resultId, ...requestOptions }) =>
        async () => {
          const response = await requestWithDefaults(requestOptions);
          const result = responseGetPath ? get(responseGetPath, response) : response;
          return resultId ? { resultId, result } : result;
        },
      requestsOptions
    );

    const firstResult = await first(unexecutedRequestFunctions)();
    const remainingResults = await parallelLimit(tail(unexecutedRequestFunctions), limit);
    const results = [firstResult, ...remainingResults];

    return onlyReturnPopulatedResults
      ? filter(
          flow((result) => getOr(result, 'result', result), negate(isEmpty)),
          results
        )
      : results;
  };

const requestsInParallel = createRequestsInParallel(requestWithDefaults);

module.exports = {
  requestWithDefaults,
  requestsInParallel
};
