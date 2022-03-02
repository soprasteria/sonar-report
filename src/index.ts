#!/usr/bin/env node

import ejs from 'ejs';
import fs from 'fs';
import got, {OptionsOfTextResponseBody} from 'got';
import {HttpsProxyAgent} from 'hpagent';
import minimist from 'minimist';
import path from 'path';
import PropertiesReader from 'properties-reader';
import semver from 'semver';
import {HotspotResponse} from './types/hotspot';
import {HostspotsResponse} from './types/hotspots';
import {IssuesResponse} from './types/issues';
import {RulesResponse} from './types/rules';
import {SettingsResponse} from './types/settings';
import {StatusResponse} from './types/status';

const argv = minimist(process.argv.slice(2));
const properties = PropertiesReader('sonar-project.properties');

if (argv.help) {
  console.log(`SYNOPSIS
    sonar-report [OPTION]...

USAGE
    sonar-report --sonarurl https://sonarcloud.io --sonarorganization sopra-steria --project=sonar-report --application=sonar-report --noSecurityHotspot=true

DESCRIPTION
    Generate a vulnerability report from a SonarQube instance.

    Environment: 
    http_proxy : the proxy to use to reach the sonarqube instance (http://<host>:<port>)
    https_proxy : the proxy to use to reach the sonarqube instance (https://<host>:<port>)

    Parameters: 
    --project
        Name of the project, displayed in the header of the generated report

    --application
        Name of the application, displayed in the header of the generated report

    --release
        Name of the release, displayed in the header of the generated report

    --branch
        Branch in Sonarqube that we want to get the issues for

    --pullrequest
        Pull request ID in Sonarqube for which to get the issues/hotspots

    --sonarurl
        base URL of the SonarQube instance to query from

    --sonarcomponent
        ID of the component to query from

    --sonarusername
        Auth username

    --sonarpassword
        Auth password

    --sonartoken
        Auth token

    --sonarorganization
        Name of the sonarcloud.io organization

    --sinceleakperiod
        Flag to indicate if the reporting should be done since the last sonarqube leak period (delta analysis). Default is false.

    --allbugs
        Flag to indicate if the report should contain all bugs, not only vulnerabilities. Default is false

    --fixMissingRule
        Extract rules without filtering on type (even if allbugs=false). Not useful if allbugs=true. Default is false

    --noSecurityHotspot
        Set this flag for old versions of sonarQube without security hotspots (<7.3). Default is false

    --vulnerabilityPhrase
        Set to override 'Vulnerability' phrase in the report. Default 'Vulnerability'
            
    --vulnerabilityPluralPhrase
        Set to override 'Vulnerabilities' phrase in the report. Default 'Vulnerabilities'    

    --reportFile
        Destinaion of the report file. Default 'sonar-report.html'

    --help
        Display this help message`);
  process.exit();
}

function logError(context: string, error: any) {
  const errorCode =
    typeof error.code === 'undefined' || error.code === null ? '' : error.code;
  const errorMessage =
    typeof error.message === 'undefined' || error.message === null
      ? ''
      : error.message;
  const errorResponseStatusCode =
    typeof error.response === 'undefined' ||
    error.response === null ||
    error.response.statusCode === 'undefined' ||
    error.response.statusCode === null
      ? ''
      : error.response.statusCode;
  const errorResponseStatusMessage =
    typeof error.response === 'undefined' ||
    error.response === null ||
    error.response.statusMessage === 'undefined' ||
    error.response.statusMessage === null
      ? ''
      : error.response.statusMessage;
  const errorResponseBody =
    typeof error.response === 'undefined' ||
    error.response === null ||
    error.response.body === 'undefined' ||
    error.response.body === null
      ? ''
      : error.response.body;

  console.error(
    'Error while %s : %s - %s - %s - %s - %s',
    context,
    errorCode,
    errorMessage,
    errorResponseStatusCode,
    errorResponseStatusMessage,
    errorResponseBody
  );
}

(async () => {
  const severity = new Map();
  severity.set('MINOR', 0);
  severity.set('MAJOR', 1);
  severity.set('CRITICAL', 2);
  severity.set('BLOCKER', 3);

  const data = {
    date: new Date().toDateString(),
    projectName: argv.project,
    applicationName:
      argv.application || properties.get('sonar.projectKey')?.toString(),
    releaseName: argv.release,
    pullRequest: argv.pullrequest,
    branch: argv.branch,
    sinceLeakPeriod: argv.sinceleakperiod == 'true',
    deltaAnalysis: argv.sinceleakperiod == 'true' ? 'Yes' : 'No',
    previousPeriod: '',
    allBugs: argv.allbugs == 'true',
    fixMissingRule: argv.fixMissingRule == 'true',
    noSecurityHotspot: argv.noSecurityHotspot == 'true',
    vulnerabilityPhrase: argv.vulnerabilityPhrase || 'Vulnerability',
    vulnerabilityPluralPhrase:
      argv.vulnerabilityPluralPhrase || 'Vulnerabilities',
    sonarBaseURL: argv.sonarurl || properties.get('sonar.host.url')?.toString(),
    sonarOrganization: argv.sonarorganization,
    summary: {},
    rules: [] as Array<{
      key: string;
      htmlDesc: string;
      name: string;
      severity: string;
    }>,
    issues: [] as Array<{
      rule: string;
      severity: string;
      status: string;
      component: string;
      line: number;
      description: string;
      message: string;
      key: string;
    }>,
    hotspotKeys: [] as Array<string>
  };

  const leakPeriodFilter = data.sinceLeakPeriod ? '&sinceLeakPeriod=true' : '';
  const sonarComponent = argv.sonarcomponent;
  const withOrganization = data.sonarOrganization
    ? `&organization=${data.sonarOrganization}`
    : '';

  const queryOption: OptionsOfTextResponseBody = {
    prefixUrl: `${data.sonarBaseURL}/api`,
    headers: {}
  };

  // Preparing configuration if behind proxy
  if (process.env.http_proxy || process.env.https_proxy) {
    console.info(
      'Using proxy %s',
      process.env.http_proxy || process.env.https_proxy
    );
    queryOption.agent = {
      https: new HttpsProxyAgent({
        proxy: (process.env.http_proxy || process.env.https_proxy)!
      })
    };
  } else {
    console.info('No proxy configuration detected');
  }

  // get SonarQube version
  let version: semver.SemVer;
  try {
    const res = await got(`system/status`, queryOption);
    const json: StatusResponse = JSON.parse(res.body);
    version = semver.coerce(json.version)!;
    console.info('Sonarqube version: %s', version);
  } catch (error) {
    return logError('Getting version', error);
  }

  let DEFAULT_ISSUES_FILTER: string,
    DEFAULT_RULES_FILTER: string,
    ISSUE_STATUSES: string;
  const HOTSPOT_STATUSES = 'TO_REVIEW';

  if (data.noSecurityHotspot || semver.satisfies(version, '<7.3')) {
    // hotspots don't exist
    DEFAULT_ISSUES_FILTER = '&types=VULNERABILITY';
    DEFAULT_RULES_FILTER = '&types=VULNERABILITY';
    ISSUE_STATUSES = 'OPEN,CONFIRMED,REOPENED';
  } else if (semver.satisfies(version, '>=7.3 && <7.8')) {
    // hotspots are stored in the /issues endpoint but issue status doesn't include TO_REVIEW,IN_REVIEW yet
    DEFAULT_ISSUES_FILTER = '&types=VULNERABILITY,SECURITY_HOTSPOT';
    DEFAULT_RULES_FILTER = '&types=VULNERABILITY,SECURITY_HOTSPOT';
    ISSUE_STATUSES = 'OPEN,CONFIRMED,REOPENED';
  } else if (semver.satisfies(version, '>=7.8 && <8.2')) {
    // hotspots are stored in the /issues endpoint and issue status includes TO_REVIEW,IN_REVIEW
    DEFAULT_ISSUES_FILTER = '&types=VULNERABILITY,SECURITY_HOTSPOT';
    DEFAULT_RULES_FILTER = '&types=VULNERABILITY,SECURITY_HOTSPOT';
    ISSUE_STATUSES = 'OPEN,CONFIRMED,REOPENED,TO_REVIEW,IN_REVIEW';
  } else {
    // version >= 8.2
    // hotspots are in a dedicated endpoint: rules have type SECURITY_HOTSPOT but issues don't
    DEFAULT_ISSUES_FILTER = '&types=VULNERABILITY';
    DEFAULT_RULES_FILTER = '&types=VULNERABILITY,SECURITY_HOTSPOT';
    ISSUE_STATUSES = 'OPEN,CONFIRMED,REOPENED';
  }

  // filters for getting rules and issues
  let filterRule = DEFAULT_RULES_FILTER;
  let filterIssue = DEFAULT_ISSUES_FILTER;
  let filterHotspots = '';

  if (data.allBugs) {
    filterRule = '';
    filterIssue = '';
  }

  if (data.pullRequest) {
    filterIssue = filterIssue + '&pullRequest=' + data.pullRequest;
    filterHotspots = filterHotspots + '&pullRequest=' + data.pullRequest;
  }

  if (data.branch) {
    filterIssue = filterIssue + '&branch=' + data.branch;
    filterHotspots = filterHotspots + '&branch=' + data.branch;
  }

  if (data.fixMissingRule) {
    filterRule = '';
  }

  if (argv.sonarusername && argv.sonarpassword) {
    // Form authentication with username/password
    try {
      const response = await got.post(`authentication/login`, {
        ...queryOption,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `login=${encodeURIComponent(
          argv.sonarusername
        )}&password=${encodeURIComponent(argv.sonarpassword)}`
      });
      queryOption.headers!['Cookie'] = response.headers['set-cookie']!.map(
        cookie => cookie.split(';')[0]
      ).join('; ');
    } catch (error) {
      return logError('Logging in', error);
    }
  } else if (argv.sonartoken) {
    // Basic authentication with user token
    queryOption.headers!['Authorization'] =
      'Basic ' + Buffer.from(argv.sonartoken + ':').toString('base64');
  }

  if (data.sinceLeakPeriod) {
    const res = await got(
      `settings/values?keys=sonar.leak.period`,
      queryOption
    );
    const json: SettingsResponse = JSON.parse(res.body);
    if (json.settings.length) data.previousPeriod = json.settings[0].value;
  }

  {
    const pageSize = 500;
    const maxResults = 10000;
    const maxPage = maxResults / pageSize;
    let page = 1;
    let nbResults;
    do {
      try {
        const response = await got(
          `rules/search?activation=true&ps=${pageSize}&p=${page}${filterRule}${withOrganization}`,
          queryOption
        );
        page++;
        const json: RulesResponse = JSON.parse(response.body);
        nbResults = json.rules.length;
        data.rules = data.rules.concat(
          json.rules.map(rule => ({
            key: rule.key,
            htmlDesc: rule.htmlDesc,
            name: rule.name,
            severity: rule.severity
          }))
        );
      } catch (error) {
        return logError('Getting rules', error);
      }
    } while (nbResults === pageSize && page <= maxPage);
  }

  {
    const pageSize = 500;
    const maxResults = 10000;
    const maxPage = maxResults / pageSize;
    let page = 1;
    let nbResults;
    /** Get all statuses except "REVIEWED".
     * Actions in sonarQube vs status in security hotspot (sonar >= 7):
     * - resolve as reviewed
     *    "resolution": "FIXED"
     *    "status": "REVIEWED"
     * - open as vulnerability
     *    "status": "OPEN"
     * - set as in review
     *    "status": "IN_REVIEW"
     */
    do {
      try {
        const response = await got(
          `issues/search?componentKeys=${sonarComponent}&ps=${pageSize}&p=${page}&statuses=${ISSUE_STATUSES}&resolutions=&s=STATUS&asc=no${leakPeriodFilter}${filterIssue}${withOrganization}`,
          queryOption
        );
        page++;
        const json: IssuesResponse = JSON.parse(response.body);
        nbResults = json.issues.length;
        data.issues = data.issues.concat(
          json.issues.map(issue => {
            const rule = data.rules.find(oneRule => oneRule.key === issue.rule);
            return {
              rule: issue.rule,
              // For security hotspots, the vulnerabilities show without a severity before they are confirmed
              // In this case, get the severity from the rule
              severity: issue.severity || rule ? rule!.severity : '',
              status: issue.status,
              // Take only filename with path, without project name
              component: issue.component.split(':').pop() || '',
              line: issue.line,
              description: rule ? rule.name : '/',
              message: issue.message,
              key: issue.key
            };
          })
        );
      } catch (error) {
        return logError('Getting issues', error);
      }
    } while (nbResults === pageSize && page <= maxPage);

    if (semver.satisfies(version, '>=8.2') && !data.noSecurityHotspot) {
      // 1) Listing hotspots with hotspots/search
      const pageSize = 500;
      const maxResults = 10000;
      const maxPage = maxResults / pageSize;
      let page = 1;
      let nbResults;
      do {
        try {
          const response = await got(
            `hotspots/search?projectKey=${sonarComponent}${filterHotspots}${withOrganization}&ps=${pageSize}&p=${page}&statuses=${HOTSPOT_STATUSES}`,
            queryOption
          );
          page++;
          const json: HostspotsResponse = JSON.parse(response.body);
          nbResults = json.hotspots.length;
          data.hotspotKeys = data.hotspotKeys.concat(
            json.hotspots.map(hotspot => hotspot.key)
          );
        } catch (error) {
          return logError('Getting hotspots list', error);
        }
      } while (nbResults === pageSize && page <= maxPage);

      // 2) Getting hotspots details with hotspots/show
      for (const hotspotKey of data.hotspotKeys) {
        try {
          const response = await got(
            `hotspots/show?hotspot=${hotspotKey}`,
            queryOption
          );
          const hotspot: HotspotResponse = JSON.parse(response.body);
          data.issues.push({
            rule: hotspot.rule.key,
            severity: hotspot.rule.vulnerabilityProbability,
            status: hotspot.status,
            // Take only filename with path, without project name
            component: hotspot.component.key.split(':').pop() || '',
            line: hotspot.line,
            description: hotspot.rule ? hotspot.rule.name : '/',
            message: hotspot.message,
            key: hotspot.key
          });
        } catch (error) {
          return logError('Getting hotspots details', error);
        }
      }
    }

    data.issues.sort(
      (a, b) => severity.get(b.severity) - severity.get(a.severity)
    );

    data.summary = {
      blocker: data.issues.filter(issue => issue.severity === 'BLOCKER').length,
      critical: data.issues.filter(issue => issue.severity === 'CRITICAL')
        .length,
      major: data.issues.filter(issue => issue.severity === 'MAJOR').length,
      minor: data.issues.filter(issue => issue.severity === 'MINOR').length
    };
  }

  ejs.renderFile(`${path.resolve()}/index.ejs`, data, {}, (err, str) => {
    if (err) return console.error(err);
    fs.writeFile(argv.reportFile || 'sonar-report.html', str, fsErr => {
      if (fsErr) return console.log(fsErr);
      console.log(
        'Report available: ' + (argv.reportFile || 'sonar-report.html')
      );
    });
  });
})();
