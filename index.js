#!/usr/bin/env node

const argv = require("minimist")(process.argv.slice(2));
const request = require("sync-request");
const ejs = require("ejs");

if (argv.help) {
  console.log(`SYNOPSIS
    sonar-report [OPTION]...

USAGE
    sonar-report --project=MyProject --application=MyApp --release=v1.0.0 --sonarurl=http://my.sonar.example.com --sonarcomponent=myapp:1.0.0 --sinceleakperiod=true > /tmp/sonar-report

DESCRIPTION
    Generate a vulnerability report from a SonarQube instance.

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
const options = { headers: {} };

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

{
  const username = argv.sonarusername;
  const password = argv.sonarpassword;
  const token = argv.sonartoken;
  if (username && password) {
    // Form authentication with username/password
    const res = request(
      "POST",
      `${sonarBaseURL}/api/authentication/login`, {
        body: `login=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    options.headers["Cookie"] = res.headers['set-cookie'].map(cookie => cookie.split(';')[0]).join('; ');
  } else if (token) {
    // Basic authentication with user token
    options.headers["Authorization"] = "Basic " + Buffer.from(token + ":").toString("base64");
  }
}

if (data.sinceLeakPeriod) {
  const res = request(
    "GET",
    `${sonarBaseURL}/api/settings/values?keys=sonar.leak.period`,
    options
  );
  const json = JSON.parse(res.getBody());
  data.previousPeriod = json.settings[0].value;
}

{
  const pageSize = 500;
  let page = 1;
  let nbResults;

  do {
    const res = request(
      "GET",
      `${sonarBaseURL}/api/rules/search?activation=true&ps=${pageSize}&p=${page}${filterRule}`,
      options
    );
    page++;
    const json = JSON.parse(res.getBody());
    nbResults = json.rules.length;
    data.rules = data.rules.concat(json.rules.map(rule => ({
      key: rule.key,
      htmlDesc: rule.htmlDesc,
      name: rule.name,
      severity: rule.severity
    })));
  } while (nbResults === pageSize);

}

{
  const pageSize = 500;
  let page = 1;
  let nbResults;
  do {
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
    let query = `${sonarBaseURL}/api/issues/search?componentKeys=${sonarComponent}&ps=${pageSize}&p=${page}&statuses=${OPEN_STATUSES}&resolutions=&s=STATUS&asc=no${leakPeriodFilter}${filterIssue}${withOrganization}`
    //console.log(query)
    const res = request(
      "GET",
      query,
      options
    );
    page++;
    const json = JSON.parse(res.getBody());
    nbResults = json.issues.length;
    data.issues = data.issues.concat(json.issues.map(issue => {
      const rule = data.rules.find(rule => rule.key === issue.rule);
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
