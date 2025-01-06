const { isEmpty, get } = require('lodash/fp');
const reduce = require('lodash/fp/reduce').convert({ cap: false });

const validateStringOptions = (stringOptionsErrorMessages, options, otherErrors = []) =>
  reduce((agg, message, optionName) => {
    const isString = typeof options[optionName].value === 'string';
    const isEmptyString = isString && isEmpty(options[optionName].value);

    return !isString || isEmptyString
      ? agg.concat({
          key: optionName,
          message
        })
      : agg;
  }, otherErrors)(stringOptionsErrorMessages);

const validateUrlOption = (options, urlKey = 'url') => {
  let allValidationErrors = [];

  const urlValue = get([urlKey, 'value'], options);

  if (urlValue.endsWith('/')) {
    allValidationErrors = allValidationErrors.concat({
      key: urlKey,
      message: 'Your Url must not end with a /'
    });
  }

  if (urlValue) {
    try {
      new URL(urlValue);
    } catch (_) {
      allValidationErrors = allValidationErrors.concat({
        key: urlKey,
        message:
          'What is currently provided is not a valid URL. You must provide a valid Instance URL.'
      });
    }
  }

  return allValidationErrors;
};

module.exports = {
  validateStringOptions,
  validateUrlOption
};
