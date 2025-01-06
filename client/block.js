'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  searchResult: Ember.computed.alias('details.searchResult'),
  expandableTitleStates: Ember.computed.alias('block._state.expandableTitleStates'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  init: function () {
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.expandableTitleStates', {});
    }

    this._super(...arguments);
  },
  actions: {
    toggleExpandableTitle: function (index) {
      this.set(
        `block._state.expandableTitleStates.${index}`,
        !this.get(`block._state.expandableTitleStates.${index}`)
      );
    }
  }
});
