'use strict';

const request = require('postman-request');
const { version: packageVersion } = require('./package.json');
const async = require('async');
const _ = require('lodash');
const util = require('util');

const MAX_PARALLEL_LOOKUPS = 10;
const USER_AGENT = `vulncheck-polarity-integration-v${packageVersion}`;

let Logger;
let requestWithDefaults;
let requestWithDefaultsAsync;

function startup(logger) {
  Logger = logger;
  let defaults = {};

  requestWithDefaults = request.defaults(defaults);
  requestWithDefaultsAsync = util.promisify(requestWithDefaults);
}

/**
 * Helper method that creates a fully formed JSON payload for a single error
 * @param msg
 * @param pointer
 * @param httpCode
 * @param code
 * @param title
 * @returns {{errors: *[]}}
 * @private
 */
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'ES_' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

const parseDescription = (rawDescription) => {
  try {
    return _.filter(rawDescription.body.data[0].descriptions, {
      lang: 'en'
    })[0].value;
  } catch (e) {
    return 'N/A';
  }
};

function _handleRequestError(err, response, body, options, cb) {
  if (err) {
    cb(
      _createJsonErrorPayload(
        'Unable to connect to VulnCheck server',
        null,
        '500',
        '2A',
        'VulnCheck HTTP Request Failed',
        {
          err: err
        }
      )
    );
    return;
  }

  if (response.statusCode === 403 || response.statusCode === 401) {
    return cb({
      detail: 'You do not have permission to access VulnCheck.  Validate your API key.'
    });
    return;
  }

  // 404 is returned if the entity has no result at all
  if (response.statusCode === 404) return cb();

  if (response.statusCode !== 200) {
    return cb(
      _createJsonErrorPayload(
        response.statusMessage,
        null,
        response.statusCode,
        '2A',
        'VulnCheck HTTP Request Failed',
        {
          response: response,
          body: body
        }
      )
    );
  }

  cb(null, body);
}

async function doLookup(entities, options, cb) {
  Logger.trace({ entities }, 'doLookup');

  options.subscriptionUrl = options.subscriptionUrl.endsWith('/')
    ? options.subscriptionUrl
    : options.subscriptionUrl + '/';

  getVulnInfo(entities, options.premiumApi, options, cb);
}

async function onMessage(payload, options, cb) {
  options.subscriptionUrl = options.subscriptionUrl.endsWith('/')
    ? options.subscriptionUrl
    : options.subscriptionUrl + '/';
  const { entity, action } = payload;
  switch (action) {
    case 'GET_EXPLOITS':
      try {
        const exploits = await getExploits(entity, options);
        Logger.trace({ exploits }, 'GET_EXPLOITS');
        cb(null, exploits);
      } catch (error) {
        Logger.error(error, 'Error fetching exploits');
        cb(error);
      }
      break;
    case 'GET_THREAT_ACTORS':
      try {
        const threatActors = await getThreatActors(entity, options);
        Logger.trace({ threatActors }, 'GET_THREAT_ACTORS');
        cb(null, threatActors);
      } catch (error) {
        Logger.error(error, 'error fetching threat actors');
        cb(error);
      }
      break;
  }
}

async function getExploits(entity, options) {
  return new Promise((resolve, reject) => {
    const exploitLookupOptions = {
      uri: options.subscriptionUrl + 'v3/index/vulncheck-kev/' + '?cve=' + entity.value,
      method: 'GET',
      headers: {
        Authorization: options.apiKey,
        'User-Agent': USER_AGENT
      },
      json: true
    };
    Logger.debug({ exploitLookupOptions }, 'Request Options for Type Exploit Lookup');
    requestWithDefaults(exploitLookupOptions, function (err, response, body) {
      _handleRequestError(err, response, body, options, function (err, exploitResult) {
        if (err) {
          Logger.error(err, `Error Looking up {${entity.value}}`);
          return reject(err);
        }
        if (exploitResult.data.length > 0) {
          resolve(exploitResult);
        } else {
          resolve([]);
        }
      });
    });
  });
}

async function getThreatActors(entity, options) {
  return new Promise((resolve, reject) => {
    const threatActorLookupOptions = {
      uri: options.subscriptionUrl + 'v3/index/threat-actors',
      qs: {
        cve: entity.value
      },
      method: 'GET',
      headers: {
        Authorization: options.apiKey,
        'User-Agent': USER_AGENT
      },
      json: true
    };
    Logger.debug({ threatActorLookupOptions }, 'Request Options for Type Threat Actor Lookup');
    requestWithDefaults(threatActorLookupOptions, function (err, response, body) {
      _handleRequestError(err, response, body, options, function (err, threatActorResult) {
        if (err) {
          Logger.error(err, `Error Looking up {${entity.value}}`);
          return reject(err);
        }
        if (threatActorResult.data.length > 0) {
          resolve(threatActorResult);
        } else {
          resolve([]);
        }
      });
    });
  });
}

const getVulnInfo = (entities, usePremium, options, cb) => {
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      method: 'GET',
      uri: `${options.subscriptionUrl}${usePremium ? 'v3/index/vulncheck-nvd2' : 'v3/index/nist-nvd2'}`,
      qs: {
        cve: entity.value
      },
      headers: {
        Authorization: options.apiKey,
        'User-Agent': USER_AGENT
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'Request Options');

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          done(processedResult);
          return;
        }

        done(null, processedResult);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body.data[0] === null || result.body.data[0].length === 0) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: getSummaryTags(result),
            details: {
              ...result.body.data[0],
              description: parseDescription(result),
              sourceIdentifier: _.get(result, 'body.data[0].sourceIdentifier', 'N/A'),
              vulnStatus: _.get(result, 'body.data[0].vulnStatus', 'N/A'),
              published: _.get(result, 'body.data[0].published', 'N/A'),
              lastModified: _.get(result, 'body.data[0].lastModified', 'N/A'),
              vendors: getUniqueCPEVendors(result.body.data[0].vcVulnerableCPEs),
              products: getUniqueCPEProducts(result.body.data[0].vcVulnerableCPEs),
              apiService: usePremium ? 'premium' : 'community'
            }
          }
        });
      }
    });

    Logger.trace({ lookupResults }, 'Lookup Results');
    cb(null, lookupResults);
  });
};

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity,
      body
    };
  } else if (res.statusCode === 400) {
    if (body.message.includes('Request is not a valid routable IPv4 address')) {
      result = {
        entity: entity,
        body: null
      };
    } else {
      result = {
        error: 'Bad Request',
        detail: body.message
      };
    }
  } else if (res.statusCode === 404) {
    result = {
      entity: entity,
      body: null
    };
  } else if (res.statusCode === 429) {
    result = {
      entity,
      statusCode: res ? res.statusCode : 'Unknown',
      error: 'API Limit Reached',
      detail: 'API Limit Reached',
      body
    };
  } else if (res.statusCode === 401) {
    result = {
      entity,
      statusCode: res ? res.statusCode : 'Unknown',
      error: 'Invalid API Key',
      detail: 'Invalid API Key',
      body
    };
  } else {
    result = {
      error: 'Unexpected Error',
      statusCode: res ? res.statusCode : 'Unknown',
      detail: 'An unexpected error occurred',
      body
    };
  }

  return result;
}

function errorToPojo(err) {
  return err instanceof Error
    ? {
        ...err,
        name: err.name,
        message: err.message,
        stack: err.stack,
        detail: err.message ? err.message : err.detail ? err.detail : 'Unexpected error encountered'
      }
    : err;
}

const getUniqueCPEVendors = (data) => {
  if (data) {
    let vendorTags = new Set();

    data.forEach(function (cpe) {
      vendorTags.add(cpe.split(':')[3]);
    });

    return [...vendorTags];
  }
};

const getUniqueCPEProducts = (data) => {
  if (data) {
    let productTags = new Set();

    data.forEach(function (cpe) {
      productTags.add(cpe.split(':')[4]);
    });

    return [...productTags];
  }
};

const getSummaryTags = (data) => {
  let tags = [];

  if (!data.body.data[0]) {
    return ['CVE has not been reported'];
  }

  if (data.limitHit) {
    return ['Lookup limit reached'];
  }

  if (data.body.data[0].metrics.cvssMetricV40) {
    tags.push(`CVSS v4: ${data.body.data[0].metrics.cvssMetricV40[0].cvssData.baseScore}`);
  } else if (data.body.data[0].metrics.cvssMetricV31) {
    tags.push(`CVSS v3: ${data.body.data[0].metrics.cvssMetricV31[0].cvssData.baseScore}`);
  } else if (data.body.data[0].metrics.cvssMetricV2) {
    tags.push(`CVSS v2: ${data.body.data[0].metrics.cvssMetricV2[0].cvssData.baseScore}`);
  }

  if (data.body.data[0].cisaExploitAdd) {
    tags.push(`CISA Known Exploited`);
  }

  if (data.body.data[0].vcVulnerableCPEs) {
    //let cpeData = data.body.data[0].vcVulnerableCPEs;
    let vendorTags = getUniqueCPEVendors(data.body.data[0].vcVulnerableCPEs);
    let productTags = getUniqueCPEProducts(data.body.data[0].vcVulnerableCPEs);
    [...new Set(vendorTags)].forEach(function (cpeVendor) {
      tags.push(`Vendor: ${cpeVendor}`);
    });
    if (productTags.length == 1) {
      [...new Set(productTags)].forEach(function (cpeProduct) {
        tags.push(`Product: ${cpeProduct}`);
      });
    } else {
      tags.push(`Product: ${[...new Set(productTags)][0]} + ${[...new Set(productTags)].length - 1}`);
    }
  }

  if (tags.length === 0) {
    tags.push(data.body.data[0].id);
  }

  return tags;
};

function validateOptions(userOptions, cb) {
  const errors = [];

  if (userOptions.premiumApi.value === true && userOptions.apiKey.value.length === 0) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a VulnCheck API key if using the subscription API'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  onMessage,
  validateOptions
};
