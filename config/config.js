module.exports = {
  name: 'VulnCheck',
  acronym: 'VC',
  description: 'TODO',
  entityTypes: ['cve'],
  defaultColor: 'light-blue',
  onDemandOnly: true,
  styles: ['./client/styles.less'],
  block: {
    component: {
      file: './client/block.js'
    },
    template: {
      file: './client/block.hbs'
    }
  },
  request: {
    cert: '',
    key: '',
    passphrase: '',
    ca: '',
    proxy: ''
  },
  logging: {
    level: 'info'
  },
  options: [
    {
      key: 'url',
      name: 'VulnChck API URL',
      description:
        'The base URL of the VulnChck API including the scheme (i.e., https://)',
      default: 'https://api.vulncheck.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'apiToken',
      name: 'API Token',
      description: 'Your API Token',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
