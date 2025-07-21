'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  tags: Ember.computed.alias('details.tags'),
  trustLevel: Ember.computed('details.trust_level', function () {
    let trustLevel = this.get('details.trust_level');
    if (trustLevel === '1') {
      return '1 - Reasonably Ignore';
    }
    if (trustLevel === '2') {
      return '2 - Commonly Seen';
    }
    return trustLevel;
  }),
  showAllTags: false,
  showCopyMessage: false,
  maxCPEsToShow: 1,
  maxReferencesToShow: 1,
  expandableTitleStates: {},
  uniqueIdPrefix: '',
  activeTab: 'details',
  cpeToShow: Ember.computed('block._state.showCPE', function () {
    let cpes;
    cpes = this.get('details.vcVulnerableCPEs');

    if (this.get('block._state.showCPE')) {
      return cpes;
    }
    return cpes.slice(0, this.maxCPEsToShow);
  }),
  referencesToShow: Ember.computed('block._state.showReferences', function () {
    let references;
    references = this.get('details.references');

    if (this.get('block._state.showReferences')) {
      return references;
    }
    return references.slice(0, this.maxReferencesToShow);
  }),
  exploitReferencesToShow: Ember.computed('block._state.showExploitRefercnes', function () {
    let exploitReferences;
    exploitReferences = this.get('details.exploitsData.data.0.vulncheck_reported_exploitation');

    if (this.get('block._state.showExploitRefercnes')) {
      return exploitReferences;
    }
    return exploitReferences.slice(0, this.maxReferencesToShow);
  }),
  exploitsToShow: Ember.computed('block._state.showExploits', function () {
    let exploits;
    exploits = this.get('details.exploitsData.data.0.vulncheck_xdb');

    if (this.get('block._state.showExploits')) {
      return exploits;
    }
    return exploits.slice(0, this.maxReferencesToShow);
  }),
  init () {
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.activeTab', 'info');
    }

    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));

    this._super(...arguments);
  },
  getExploits: function () {
    const payload = {
      action: 'GET_EXPLOITS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorExploits', '');
    this.set('block._state.loadingExploits', true);
    this.sendIntegrationMessage(payload)
      .then((exploitsData) => {
        this.set('block.data.details.exploitsData', JSON.parse(exploitsData));
        this.set('exploits', {});
        this.set('showExploits', true);
        this.set('block._state.loadedExploits', true);
      })
      .catch((err) => {
        this.set('block._state.errorExploits', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingExploits', false);
      });
  },
  getThreatActors: function () {
    const payload = {
      action: 'GET_THREAT_ACTORS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorThreatActors', '');
    this.set('block._state.loadingThreatActors', true);
    this.sendIntegrationMessage(payload)
      .then((threatActorsData) => {
        this.set('block.data.details.threatActorsData', JSON.parse(threatActorsData).data.sort((a, b) => {return a["threat_actor_name"].localeCompare(b["threat_actor_name"]);}));
        this.set('threatActors', {});
        this.set('showThreatActors', true);
        this.set('block._state.loadedThreatActors', true);
      })
      .catch((err) => {
        this.set('block._state.errorThreatActors', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingThreatActors', false);
      });
  },
  actions: {
    toggleCPE: function () {
      this.toggleProperty('block._state.showCPE');
    },
    toggleReferences: function () {
      this.toggleProperty('block._state.showReferences');
    },
    toggleExploitReferences: function () {
      this.toggleProperty('block._state.showExploitRefercnes');
    },
    toggleExploits: function () {
      this.toggleProperty('block._state.showExploits');
    },
    toggleThreatActors: function () {
      this.toggleProperty('block._state.showThreatActors');
    },
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
      switch (tabName) {
        // exploits tab requires exploit data
        case 'exploits':
          // Make sure we only load the data once
          if (!this.get('block._state.loadedExploits')) {
            this.getExploits();
          }
          break;
        case 'threatActors':
          // Make sure we only load the data once
          if (!this.get('block._state.loadedThreatActors')) {
            this.getThreatActors();
          }
          break;
      }
    },
    copyData: function () {
      const savedShowAllTags = this.get('block._state.showAllTags');
      const savedActiveTab = this.get('block._state.activeTab');

      let containerId = null;

      const idTypes = {
        info: `information-container-${this.get('uniqueIdPrefix')}`,
        activity: `activity-container-${this.get('uniqueIdPrefix')}`
      };

      if (this.get('block.userOptions.subscriptionApi')) {
        if (this.get('block.entity.type') === 'cve') {
          containerId = `cve-container-${this.get('uniqueIdPrefix')}`;
        } else {
          containerId = idTypes[this.get('block._state.activeTab')];
        }
      } else {
        containerId = `community-container-${this.get('uniqueIdPrefix')}`;
      }

      this.set('block._state.showAllTags', true);

      Ember.run.scheduleOnce('afterRender', this, this.copyElementToClipboard, containerId);
      Ember.run.scheduleOnce('destroy', this, this.restoreCopyState, savedActiveTab, savedShowAllTags);
    },
    toggleExpandableTitle: function (index) {
      const modifiedExpandableTitleStates = Object.assign({}, this.get('expandableTitleStates'), {
        [index]: !this.get('expandableTitleStates')[index]
      });
      this.set(`expandableTitleStates`, modifiedExpandableTitleStates);
    }
  },
  copyElementToClipboard (element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();

    range.selectNode(typeof element === 'string' ? document.getElementById(element) : element);
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  restoreCopyState (savedActiveTab, savedShowAllTags) {
    this.set('activeTab', savedActiveTab);
    this.set('showCopyMessage', true);

    this.set('block._state.showAllTags', savedShowAllTags);

    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set('showCopyMessage', false);
      }
    }, 2000);
  }
});
