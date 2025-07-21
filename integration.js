'use strict';

const request = require('postman-request');
const config = require('./config/config');
const { version: packageVersion } = require('./package.json');
const async = require('async');
const fs = require('fs');
const _ = require('lodash');
const util = require('util');
const fp = require('lodash/fp');

const MAX_PARALLEL_LOOKUPS = 10;
const USER_AGENT = `vulncheck-polarity-integration-v${packageVersion}`;

let Logger;
let requestWithDefaults;
let requestWithDefaultsAsync;

function startup (logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
  requestWithDefaultsAsync = util.promisify(requestWithDefaults);
}

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

  if (response.statusCode === 429) {
    // This means the user has reached their request limit for the API key.  In this case,
    // we don't treat it as an error and just return no results.  In the future, integrations
    // might allow non-error messages to be passed back to the user such as (VT query limit reached)
    if (!throttleCache.has(options.apiKey)) {
      setTimeout(
        _removeFromThrottleCache(options.apiKey),
        options.lookupThrottleDuration * 60 * 1000
      );
      // false here indicates that the throttle warning message has not been shown to the user yet
      throttleCache.set(options.apiKey, false);
    }

    if (options.warnOnLookupLimit) {
      cb('API Lookup Limit Reached');
    } else if (options.warnOnThrottle) {
      throttleCache.set(options.apiKey, true);
      cb(`Throttling lookups for ${options.lookupThrottleDuration} minute`, []);
    } else {
      cb(null, { __keyLimitReached: true });
    }

    return;
  }

  if (response.statusCode === 403 || response.statusCode === 401) {
    cb('You do not have permission to access VulnCheck.  Validate your API key.');
    return;
  }

  // 404 is returned if the entity has no result at all
  if (response.statusCode === 404) return cb();

  if (response.statusCode !== 200) {
    if (body) {
      cb(body);
    } else {
      cb(
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
    return;
  }

  cb(null, body);
}

async function doLookup (entities, options, cb) {
  Logger.trace({ entities }, 'doLookup');
  const { validIps, validCves } = getValidIpsAndCves(entities);

  if (options.premiumApi) {
    // subscription API searches both IPs and CVEs
    try {
      await useVulnCheckPremiumApi(validCves, options, cb);
    } catch (error) {
      Logger.error(error);
      cb(errorToPojo(error));
    }
  } else {
    // community api only searches IPs
    useVulnCheckCommunityApi(validCves, options, cb);
  }
}

async function onMessage(payload, options, cb) {
  const { entity, action } = payload;
  switch (action) {
    case 'GET_EXPLOITS':
      try {
        const exploits = await getExploits(entity, options);
        Logger.trace({ exploits }, 'GET_EXPLOITS');
        cb(null, exploits);
      } catch (error) {
        cb(error);
      }
      break;
    case 'GET_THREAT_ACTORS':
      try {
        const threatActors = await getThreatActors(entity, options);
        cb(null, threatActors);
      } catch (error) {
        cb(error);
      }
      break;
  }
}


/**
 * Given an array of entity objects, only return valid IPs and CVEs.
 *
 * @param entities
 * @returns {*}
 */
const getValidIpsAndCves = (entities) => {
  const validIps = [];
  const validCves = [];

  entities.forEach((entity) => {
    if (entity.isIP && isValidIp(entity)) {
      validIps.push(entity);
    } else if (entity.type === 'cve') {
      validCves.push(entity);
    }
  });

  return { validIps, validCves };
};

async function getExploits(entity, options) {
  return new Promise((resolve, reject) => {
    const exploitLookupOptions = {
      uri: options.subscriptionUrl + 'v3/index/vulncheck-kev/' + '?cve=' + entity.value,
      method: 'GET',
      headers: {
        Authorization: options.apiKey,
        'User-Agent': USER_AGENT
      }
    };
    Logger.debug(
      { exploitLookupOptions },
      'Request Options for Type Exploit Lookup'
    );
    requestWithDefaults(exploitLookupOptions, function (err, response, body) {
      _handleRequestError(err, response, body, options, function (err, exploitResult) {
        if (err) {
          Logger.error(err, `Error Looking up {${entity.value}}`);
          return reject(err);
        }
        if (JSON.parse(exploitResult).data.length > 0) {
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
      uri: options.subscriptionUrl + 'v3/index/threat-actors/' + '?cve=' + entity.value,
      method: 'GET',
      headers: {
        Authorization: options.apiKey,
        'User-Agent': USER_AGENT
      }
    };
    Logger.debug(
      { threatActorLookupOptions },
      'Request Options for Type Threat Actor Lookup'
    );
    requestWithDefaults(threatActorLookupOptions, function (err, response, body) {
      _handleRequestError(err, response, body, options, function (err, threatActorResult) {
        if (err) {
          Logger.error(err, `Error Looking up {${entity.value}}`);
          return reject(err);
        }
        if (JSON.parse(threatActorResult).data.length > 0) {
          resolve(threatActorResult);
        } else {
          resolve([]);
        }
      });
    });
  });
}

const useVulnCheckCommunityApi = (entities, options, cb) => {
  /** Logger.trace('Running the Community API Lookup.'); */
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      method: 'GET',
      uri: options.subscriptionUrl + 'v3/index/nist-nvd2/' + '?cve=' + entity.value,
      headers: {
        Authorization: options.apiKey,
        'User-Agent': USER_AGENT
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'request options');

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          Logger.trace(processedResult)
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
      //Logger.trace({ result }, 'Community Result');
      //let cpevendors = getUniqueCPEVendors(result.body.data[0].vcVulnerableCPEs);
      //Logger.trace({cpevendors}, 'Vendors');
      if ((result.body === null || result.body.length === 0)) {
        Logger.trace('No Data Found.');
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        Logger.trace('Results found, trying to parse.');
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: getCommunitySummaryTags(result),
            details: {
              ...result.body.data[0],
              description: _.filter(result.body.data[0].descriptions, {'lang': 'en'})[0].value,
              sourceIdentifier: result.body.data[0].sourceIdentifier,
              vulnStatus: result.body.data[0].vulnStatus,
              published: result.body.data[0].published,
              lastModified: result.body.data[0].lastModified,
              vendors: getUniqueCPEVendors(result.body.data[0].vcVulnerableCPEs),
              products: getUniqueCPEProducts(result.body.data[0].vcVulnerableCPEs),
              apiService: 'community',
              usingApiKey: options.apiKey ? true : false,
              hasResult: result.body !== null
            }
          }
        });
      }
    });

    //Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
};

const useVulnCheckPremiumApi = (entities, options, cb) => {
  /** Logger.trace('Running the Community API Lookup.'); */
  let lookupResults = [];
  let tasks = [];

  entities.forEach((entity) => {
    let requestOptions = {
      method: 'GET',
      uri: options.subscriptionUrl + 'v3/index/vulncheck-nvd2/' + '?cve=' + entity.value,
      headers: {
        Authorization: options.apiKey,
        'User-Agent': USER_AGENT
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'request options');

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          Logger.trace(processedResult)
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
      //Logger.trace({ result }, 'Community Result');
      //let cpevendors = getUniqueCPEVendors(result.body.data[0].vcVulnerableCPEs);
      //Logger.trace({cpevendors}, 'Vendors');
      if ((result.body === null || result.body.length === 0)) {
        Logger.trace('No Data Found.');
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        Logger.trace('Results found, trying to parse.');
        Logger.trace(result.entity.type, 'Result_entity');
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: getCommunitySummaryTags(result),
            details: {
              ...result.body.data[0],
              description: _.filter(result.body.data[0].descriptions, {'lang': 'en'})[0].value,
              sourceIdentifier: result.body.data[0].sourceIdentifier,
              vulnStatus: result.body.data[0].vulnStatus,
              published: result.body.data[0].published,
              lastModified: result.body.data[0].lastModified,
              vendors: getUniqueCPEVendors(result.body.data[0].vcVulnerableCPEs),
              products: getUniqueCPEProducts(result.body.data[0].vcVulnerableCPEs),
              apiService: 'premium',
              usingApiKey: options.apiKey ? true : false,
              hasResult: result.body !== null
            }
          }
        });
      }
    });

    //Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
};

function handleRestError (error, entity, res, body) {
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
      entity: entity,
      body: body
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
    // 'IP not observed scanning the internet or contained in RIOT data set.'
    result = {
      entity: entity,
      body: null
    };
  } else if (res.statusCode === 429) {
    result = {
      entity: entity,
      body: { limitHit: true }
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

function errorToPojo (err) {
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

const isLoopBackIp = (entity) => {
  return entity.startsWith('127');
};

const isLinkLocalAddress = (entity) => {
  return entity.startsWith('169');
};

const isPrivateIP = (entity) => {
  return entity.isPrivateIP === true;
};

const isValidIp = (entity) => {
  return !(isLoopBackIp(entity.value) || isLinkLocalAddress(entity.value) || isPrivateIP(entity));
};

const getUniqueCPEVendors = (data) => {
  if (data) {
    let vendorTags = [];
    //data.body.data[0].vcVulnerableCPEs.forEach(function(cpe) {
    data.forEach(function(cpe) {
      vendorTags.push(cpe.split(':')[3]);
    });
    Logger.trace([ ...new Set(vendorTags)]);
    return [ ...new Set(vendorTags)];
  }
  else {
    return;
  };
};

const getUniqueCPEProducts = (data) => {
  if (data) {
    let productTags = [];
    //data.body.data[0].vcVulnerableCPEs.forEach(function(cpe) {
    data.forEach(function(cpe) {
      productTags.push(cpe.split(':')[4]);
    });
    Logger.trace([ ...new Set(productTags)]);
    return [ ...new Set(productTags)];
  }
  else {
    return;
  };
};

const getCommunitySummaryTags = (data) => {
  Logger.trace('Attempting to parse summary tags.');
  let tags = [];

  if (!data) {
    return ['CVE has not been reported'];
  }

  if (data.limitHit) {
    return ['Lookup limit reached'];
  }

  if (data.body.data[0].metrics.cvssMetricV40) {
    tags.push(`CVSS v4: ${data.body.data[0].metrics.cvssMetricV40[0].cvssData.baseScore}`)
  }
  else if (data.body.data[0].metrics.cvssMetricV31) {
    tags.push(`CVSS v3: ${data.body.data[0].metrics.cvssMetricV31[0].cvssData.baseScore}`)
  }
  else if (data.body.data[0].metrics.cvssMetricV2) {
    tags.push(`CVSS v2: ${data.body.data[0].metrics.cvssMetricV2[0].cvssData.baseScore}`)
  }

  if (data.body.data[0].cisaExploitAdd) {
    tags.push(`CISA Known Exploited`)
  }
  
  if (data.body.data[0].vcVulnerableCPEs) {
    //let cpeData = data.body.data[0].vcVulnerableCPEs;
    let vendorTags = getUniqueCPEVendors(data.body.data[0].vcVulnerableCPEs);
    let productTags = getUniqueCPEProducts(data.body.data[0].vcVulnerableCPEs);
    [ ...new Set(vendorTags)].forEach(function(cpeVendor) {
      tags.push(`Vendor: ${cpeVendor}`)
    });
    if (productTags.length == 1) {
      [ ...new Set(productTags)].forEach(function(cpeProduct) {
        tags.push(`Product: ${cpeProduct}`)
      });
    }
    else {
      tags.push(`Product: ${[ ...new Set(productTags)][0]} + ${[ ...new Set(productTags)].length - 1}`)
    }
    
  }
  return tags;
};

function validateOptions (userOptions, cb) {
  const errors = [];

  if (userOptions.premiumApi.value === true && userOptions.apiKey.value.length === 0) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a GreyNoise API key if using the subscription API'
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
