const {
  map,
  filter,
  get,
  flow,
  eq,
  flatMap,
  uniqWith,
  isEqual,
  identity,
  first,
  toLower,
  some
} = require('lodash/fp');

const isPrivateIP = (ip) => {
  var parts = ip.split('.');
  return (
    parts[0] === '10' ||
    (parts[0] === '172' &&
      parseInt(parts[1], 10) >= 16 &&
      parseInt(parts[1], 10) <= 31) ||
    (parts[0] === '192' && parts[1] === '168')
  );
};

const removePrivateIps = (entities) =>
  filter(({ isIP, value }) => !isIP || (isIP && !isPrivateIP(value)), entities);

const getEntityTypes = (typesToGet, entities) => {
  const lowerTypesToGet =
    typeof typesToGet === 'string' ? [toLower(typesToGet)] : map(toLower, typesToGet);

  const entitiesOfTypesToGet = filter((entity) => {
    const lowerEntityTypes = map(toLower, entity.types);

    const entityTypesAreInTypesToGet = some(
      (typeToGet) => lowerEntityTypes.includes(typeToGet),
      lowerTypesToGet
    );

    return entityTypesAreInTypesToGet;
  }, entities);

  return entitiesOfTypesToGet;
};

const getResultForThisEntity = (
  entity,
  results,
  onlyOneResultExpected = false,
  onlyReturnUniqueResults = false
) =>
  flow(
    filter(flow(get('resultId'), eq(entity.value))),
    flatMap(get('result')),
    onlyReturnUniqueResults ? uniqWith(isEqual) : identity,
    onlyOneResultExpected ? first : identity
  )(results);

module.exports = {
  removePrivateIps,
  getEntityTypes,
  getResultForThisEntity
};
