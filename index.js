#!/usr/bin/env node
const argv = require("minimist")(process.argv.slice(2));
const got = require('got');
const tunnel = require('tunnel');
const ejs = require("ejs");

if (argv.help) {
  console.log(`SYNOPSIS
    sonar-report [OPTION]...

USAGE
    sonar-report --project=MyProject --application=MyApp --release=v1.0.0 --sonarurl=http://my.sonar.example.com --sonarcomponent=myapp:1.0.0 --sinceleakperiod=true > /tmp/sonar-report

DESCRIPTION
    Generate a vulnerability report from a SonarQube instance.

    Environment: 
    http_proxy : the proxy to use to reach the sonarqube instance (http://<host>:<port>)

    Parameters: 
    --project
        name of the project, displayed in the header of the generated report

    --application
        name of the application, displayed in the header of the generated report

    --release
        name of the release, displayed in the header of the generated report

    --branch
        Branch in Sonarqube that we want to get the issues for

    --pullrequest
        pull request ID in Sonarqube for which to get the issues/hotspots

    --sonarurl
        base URL of the SonarQube instance to query from

    --sonarcomponent
        id of the component to query from

    --sonarusername
        auth username

    --sonarpassword
        auth password

    --sonartoken
        auth token

    --sonarorganization
        name of the sonarcloud.io organization

    --sinceleakperiod
        flag to indicate if the reporting should be done since the last sonarqube leak period (delta analysis). Default is false.

    --allbugs
        flag to indicate if the report should contain all bugs, not only vulnerabilities. Default is false

    --fixMissingRule
        Extract rules without filtering on type (even if allbugs=false). Not useful if allbugs=true. Default is false

    --noSecurityHotspot
        Set this flag for old versions of sonarQube without security hotspots (<7.3). Default is false

    --qualityGateStatus
        Set this flag to include quality gate status in the report. Default is false
        
    --vulnerabilityPhrase
        Set to override 'Vulnerability' phrase in the report. Default 'Vulnerability'
            
    --vulnerabilityPluralPhrase
        Set to override 'Vulnerabilities' phrase in the report. Default 'Vulnerabilities'    
    
    --help
        display this help message`);
  process.exit();
}

function logError(context, error){
  var errorCode = (typeof error.code === 'undefined' || error.code === null) ? "" : error.code;
  var errorMessage = (typeof error.message === 'undefined' || error.message === null) ? "" : error.message;
  var errorResponseStatusCode = (typeof error.response === 'undefined' || error.response === null || error.response.statusCode === 'undefined' || error.response.statusCode === null ) ? "" : error.response.statusCode;
  var errorResponseStatusMessage = (typeof error.response === 'undefined' || error.response === null || error.response.statusMessage === 'undefined' || error.response.statusMessage === null ) ? "" : error.response.statusMessage;
  var errorResponseBody = (typeof error.response === 'undefined' || error.response === null || error.response.body === 'undefined' || error.response.body === null ) ? "" : error.response.body;

  console.error(
    "Error while %s : %s - %s - %s - %s - %s", 
    context, errorCode, errorMessage, errorResponseStatusCode, errorResponseStatusMessage,  errorResponseBody);  
}

(async () => {
  var severity = new Map();
  severity.set('MINOR', 0);
  severity.set('MAJOR', 1);
  severity.set('CRITICAL', 2);
  severity.set('BLOCKER', 3);
  var hotspotSeverities = {"HIGH": "CRITICAL", "MEDIUM": "MAJOR", "LOW": "MINOR"};

  const data = {
    date: new Date().toDateString(),
    projectName: argv.project,
    applicationName: argv.application,
    releaseName: argv.release,
    pullRequest: argv.pullrequest,
    branch: argv.branch,
    sinceLeakPeriod: (argv.sinceleakperiod == 'true'),
    previousPeriod: '',
    allBugs: (argv.allbugs == 'true'),
    fixMissingRule: (argv.fixMissingRule == 'true'),
    noSecurityHotspot: (argv.noSecurityHotspot == 'true'),
    vulnerabilityPhrase: argv.vulnerabilityPhrase || 'Vulnerability',
    vulnerabilityPluralPhrase: argv.vulnerabilityPluralPhrase || 'Vulnerabilities',
    // sonar URL without trailing /
    sonarBaseURL: argv.sonarurl.replace(/\/$/, ""),
    sonarOrganization: argv.sonarorganization,
    rules: [],
    issues: [],
    hotspotKeys: []
  };

  const leakPeriodFilter = data.sinceLeakPeriod ? '&sinceLeakPeriod=true' : '';
  data.deltaAnalysis = data.sinceLeakPeriod ? 'Yes' : 'No';
  const sonarBaseURL = data.sonarBaseURL;
  const sonarComponent = argv.sonarcomponent;
  const withOrganization = data.sonarOrganization ? `&organization=${data.sonarOrganization}` : '';
  var headers = {};
  var version = null;
  
  var proxy = null;
  // the tunnel agent if a forward proxy is required, or remains null
  var agent = null;
  // Preparing configuration if behind proxy
  if (process.env.http_proxy){
    proxy = process.env.http_proxy;
    var url = new URL(proxy);
    var proxyHost = url.hostname;
    var proxyPort = url.port;
    console.error('using proxy %s:%s', proxyHost, proxyPort);
    agent = {
      https: tunnel.httpsOverHttp({
          proxy: {
              host: proxyHost,
              port: proxyPort
          }
      })
    };
  }
  else{
    console.error('No proxy configuration detected');
  }
  
  //get SonarQube version
  try {
    const res = await got(`${sonarBaseURL}/api/system/status`, {
      agent,
      headers
    });
    const json = JSON.parse(res.body);
    version = json.version;
    console.error("sonarqube version: %s", version);
  } catch (error) {
      logError("getting version", error);
      return null;
  }

  let DEFAULT_ISSUES_FILTER="";
  let DEFAULT_RULES_FILTER="";
  let ISSUE_STATUSES="";
  let HOTSPOT_STATUSES="TO_REVIEW"

  if(data.noSecurityHotspot || version < "7.3"){
    // hotspots don't exist
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY"
    ISSUE_STATUSES="OPEN,CONFIRMED,REOPENED"
  }
  else if (version >= "7.3" && version < "7.8"){
    // hotspots are stored in the /issues endpoint but issue status doesn't include TO_REVIEW,IN_REVIEW yet
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    ISSUE_STATUSES="OPEN,CONFIRMED,REOPENED"
  }
  else if (version >= "7.8" && version < "8.2"){
    // hotspots are stored in the /issues endpoint and issue status includes TO_REVIEW,IN_REVIEW
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    ISSUE_STATUSES="OPEN,CONFIRMED,REOPENED,TO_REVIEW,IN_REVIEW"
  }
  else{
    // version >= 8.2
    // hotspots are in a dedicated endpoint: rules have type SECURITY_HOTSPOT but issues don't
    DEFAULT_ISSUES_FILTER="&types=VULNERABILITY"
    DEFAULT_RULES_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    ISSUE_STATUSES="OPEN,CONFIRMED,REOPENED"
  }
  

  // filters for getting rules and issues
  let filterRule = DEFAULT_RULES_FILTER;
  let filterIssue = DEFAULT_ISSUES_FILTER;
  let filterHotspots = "";
  let filterProjectStatus = "";

  if(data.allBugs){
    filterRule = "";
    filterIssue = "";
  }

  if(data.pullRequest){
    filterIssue=filterIssue + "&pullRequest=" + data.pullRequest
    filterHotspots=filterHotspots + "&pullRequest=" + data.pullRequest
    filterProjectStatus = "&pullRequest=" + data.pullRequest;
  }

  if(data.branch){
    filterIssue=filterIssue + "&branch=" + data.branch
    filterHotspots=filterHotspots + "&branch=" + data.branch
    filterProjectStatus = "&branch=" + data.branch;
  }

  if(data.fixMissingRule){
    filterRule = "";
  }


  const username = argv.sonarusername;
  const password = argv.sonarpassword;
  const token = argv.sonartoken;
  if (username && password) {
    // Form authentication with username/password
    try {
      const response = await got.post(`${sonarBaseURL}/api/authentication/login`, {
          agent,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: `login=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      });
      headers["Cookie"] = response.headers['set-cookie'].map(cookie => cookie.split(';')[0]).join('; ');
    } catch (error) {
        logError("logging in", error);
        return null;
    }
    
  } else if (token) {
    // Basic authentication with user token
    headers["Authorization"] = "Basic " + Buffer.from(token + ":").toString("base64");
  }

  if (data.sinceLeakPeriod) {
    const res = await got(`${sonarBaseURL}/api/settings/values?keys=sonar.leak.period`, {
      agent,
      headers
    });
    const json = JSON.parse(res.getBody());
    data.previousPeriod = json.settings[0].value;
  }

  if (argv.qualityGateStatus === 'true') {
      try {
          const response = await got(`${sonarBaseURL}/api/qualitygates/project_status?projectKey=${sonarComponent}${filterProjectStatus}`, {
              agent,
              headers
          });
          const json = JSON.parse(response.body);
          if (json.projectStatus.conditions) {
              for (const condition of json.projectStatus.conditions) {
                  condition.metricKey = condition.metricKey.replace(/_/g, " ");
              }
          }
          data.qualityGateStatus = json;
      } catch (error) {
          logError("getting quality gate status", error);
          return null;
      }
  }

  {
    const pageSize = 500;
    const maxResults = 10000;
    const maxPage = maxResults / pageSize;
    let page = 1;
    let nbResults;

  do {
      try {
          const response = await got(`${sonarBaseURL}/api/rules/search?activation=true&ps=${pageSize}&p=${page}${filterRule}${withOrganization}`, {
              agent,
              headers
          });
          page++;
          const json = JSON.parse(response.body);
          nbResults = json.rules.length;
          data.rules = data.rules.concat(json.rules.map(rule => ({
          key: rule.key,
          htmlDesc: rule.htmlDesc,
          name: rule.name,
          severity: rule.severity
          })));
      } catch (error) {
          logError("getting rules", error);
          return null;
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
          const response = await got(`${sonarBaseURL}/api/issues/search?componentKeys=${sonarComponent}&ps=${pageSize}&p=${page}&statuses=${ISSUE_STATUSES}&resolutions=&s=STATUS&asc=no${leakPeriodFilter}${filterIssue}${withOrganization}`, {
              agent,
              headers
          });
          page++;
          const json = JSON.parse(response.body);
          nbResults = json.issues.length;
          data.issues = data.issues.concat(json.issues.map(issue => {
            const rule = data.rules.find(oneRule => oneRule.key === issue.rule);
            const message = rule ? rule.name : "/";
            return {
              rule: issue.rule,
              // For security hotspots, the vulnerabilities show without a severity before they are confirmed
              // In this case, get the severity from the rule
              severity: (typeof issue.severity !== 'undefined') ? issue.severity : rule.severity,
              status: issue.status,
              // Take only filename with path, without project name
              component: issue.component.split(':').pop(),
              line: issue.line,
              description: message,
              message: issue.message,
              key: issue.key
            };
          }));
      } catch (error) {
        logError("getting issues", error);  
          return null;
      }
    } while (nbResults === pageSize && page <= maxPage);

    let hSeverity = "";
    if (version >= "8.2" && !data.noSecurityHotspot) {
      // 1) Listing hotspots with hotspots/search
      page = 1;
      do {
        try {
            const response = await got(`${sonarBaseURL}/api/hotspots/search?projectKey=${sonarComponent}${filterHotspots}${withOrganization}&ps=${pageSize}&p=${page}&statuses=${HOTSPOT_STATUSES}`, {
                agent,
                headers
            });
            page++;
            const json = JSON.parse(response.body);
            nbResults = json.hotspots.length;
            data.hotspotKeys.push(...json.hotspots.map(hotspot => hotspot.key));
        } catch (error) {
          logError("getting hotspots list", error);  
            return null;
        }
      } while (nbResults === pageSize && page <= maxPage);

      // 2) Getting hotspots details with hotspots/show
      for (let hotspotKey of data.hotspotKeys){
        try {
            const response = await got(`${sonarBaseURL}/api/hotspots/show?hotspot=${hotspotKey}`, {
                agent,
                headers
            });
            const hotspot = JSON.parse(response.body);
            hSeverity = hotspotSeverities[hotspot.rule.vulnerabilityProbability];
            if (hSeverity === undefined) {
              hSeverity = "MAJOR";
              console.error("Unknown hotspot severity: %s", hotspot.vulnerabilityProbability);
            }
            data.issues.push(
              {
                rule: hotspot.rule.key,
                severity: hSeverity,
                status: hotspot.status,
                // Take only filename with path, without project name
                component: hotspot.component.key.split(':').pop(),
                line: hotspot.line,
                description: hotspot.rule ? hotspot.rule.name : "/",
                message: hotspot.message,
                key: hotspot.key
              });
        } catch (error) {
          logError("getting hotspots details", error);  
            return null;
        }
      }
    }


    data.issues.sort(function (a, b) {
      return severity.get(b.severity) - severity.get(a.severity);
    });
  
    data.summary = {
      blocker: data.issues.filter(issue => issue.severity === "BLOCKER").length,
      critical: data.issues.filter(issue => issue.severity === "CRITICAL").length,
      major: data.issues.filter(issue => issue.severity === "MAJOR").length,
      minor: data.issues.filter(issue => issue.severity === "MINOR").length
    };
  }

  ejs.renderFile(`${__dirname}/index.ejs`, data, {}, (err, str) => {
    console.log(str);
  });
})();
