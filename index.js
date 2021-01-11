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
        Set this flag for old versions of sonarQube without security hotspots (<7.3?). Default is false

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

  const data = {
    date: new Date().toDateString(),
    projectName: argv.project,
    applicationName: argv.application,
    releaseName: argv.release,
    branch: argv.branch,
    sinceLeakPeriod: (argv.sinceleakperiod == 'true'),
    previousPeriod: '',
    allBugs: (argv.allbugs == 'true'),
    fixMissingRule: (argv.fixMissingRule == 'true'),
    noSecurityHotspot: (argv.noSecurityHotspot == 'true'),
    // sonar URL without trailing /
    sonarBaseURL: argv.sonarurl.replace(/\/$/, ""),
    sonarOrganization: argv.sonarorganization,
    rules: [],
    issues: []
  };

  const leakPeriodFilter = data.sinceLeakPeriod ? '&sinceLeakPeriod=true' : '';
  data.deltaAnalysis = data.sinceLeakPeriod ? 'Yes' : 'No';
  const sonarBaseURL = data.sonarBaseURL;
  const sonarComponent = argv.sonarcomponent;
  const withOrganization = data.sonarOrganization ? `&organization=${data.sonarOrganization}` : '';
  var headers = {};

  let DEFAULT_FILTER="";
  let OPEN_STATUSES="";
  // Default filter gets only vulnerabilities
  if(data.noSecurityHotspot){
    // For old versions of sonarQube (sonarQube won't accept filtering on a type that doesn't exist and will give HTTP 400 {"errors":[{"msg":"Value of parameter 'types' (SECURITY_HOTSPOT) must be one of: [CODE_SMELL, BUG, VULNERABILITY]"}]})
    DEFAULT_FILTER="&types=VULNERABILITY"
    OPEN_STATUSES="OPEN,CONFIRMED,REOPENED"
  }
  else{
    // For newer versions of sonar, rules and issues may be of type VULNERABILITY or SECURITY_HOTSPOT
    DEFAULT_FILTER="&types=VULNERABILITY,SECURITY_HOTSPOT"
    // the security hotspot adds TO_REVIEW,IN_REVIEW
    OPEN_STATUSES="OPEN,CONFIRMED,REOPENED,TO_REVIEW,IN_REVIEW"
  }

  // filters for getting rules and issues
  let filterRule = DEFAULT_FILTER;
  let filterIssue = DEFAULT_FILTER;

  if(data.allBugs){
    filterRule = "";
    filterIssue = "";
  }

  if(data.branch){
    filterIssue=filterIssue + "&branch=" + data.branch
  }

  if(data.fixMissingRule){
    filterRule = "";
  }

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
        logError("while logging in", error);
        return null;
    }
    
  } else if (token) {
    // Basic authentication with user token
    headers["Authorization"] = "Basic " + Buffer.from(token + ":").toString("base64");
  }

  if (data.sinceLeakPeriod) {
    const res = request(
      "GET",
      `${sonarBaseURL}/api/settings/values?keys=sonar.leak.period`,
      {headers}
    );
    const json = JSON.parse(res.getBody());
    data.previousPeriod = json.settings[0].value;
  }

  {
    const pageSize = 500;
    let page = 1;
    let nbResults;

  do {
      try {
          const response = await got(`${sonarBaseURL}/api/rules/search?activation=true&ps=${pageSize}&p=${page}${filterRule}`, {
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
          logError("while getting rules", error);
          return null;
      }
    } while (nbResults === pageSize);
  }

  {
    const pageSize = 500;
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
            const response = await got(`${sonarBaseURL}/api/issues/search?componentKeys=${sonarComponent}&ps=${pageSize}&p=${page}&statuses=${OPEN_STATUSES}&resolutions=&s=STATUS&asc=no${leakPeriodFilter}${filterIssue}${withOrganization}`, {
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
          logError("while getting issues", error);  
            return null;
        }
      } while (nbResults === pageSize);
  
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