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

    --sonarurl
        base URL of the SonarQube instance to query from

    --sonarcomponent
        id of the component to query from

    --sonarusername
        auth username

    --sonarpassword
        auth password

    --sinceleakperiod
        flag to indicate if the reporting should be done since the last sonarqube leak period (delta analysis). Default is false.

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
  sinceLeakPeriod: (argv.sinceleakperiod == 'true'),
  previousPeriod: '',
  sonarBaseURL: argv.sonarurl,
  rules: [],
  issues: []
};

const leakPeriodFilter = data.sinceLeakPeriod ? '&sinceLeakPeriod=true' : '';
data.deltaAnalysis = data.sinceLeakPeriod ? 'Yes' : 'No';
const sonarBaseURL = data.sonarBaseURL;
const sonarComponent = argv.sonarcomponent;
let cookies;

{
  const username = argv.sonarusername;
  const password = argv.sonarpassword;
  if (username && password) {
    const res = request(
      "POST",
      `${sonarBaseURL}/api/authentication/login`, {
        body: `login=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    cookies = res.headers['set-cookie'].map(cookie => cookie.split(';')[0]).join('; ');
  }
}

if (data.sinceLeakPeriod) {
  const res = request(
    "GET",
    `${sonarBaseURL}/api/settings/values?keys=sonar.leak.period`,
    cookies ? {
      headers: {
        'Cookie': cookies
      }
    } : undefined
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
      `${sonarBaseURL}/api/rules/search?activation=true&types=VULNERABILITY&ps=${pageSize}&p=${page}`,
      cookies ? {
        headers: {
          'Cookie': cookies
        }
      } : undefined
    );
    page++;
    const json = JSON.parse(res.getBody());
    nbResults = json.rules.length;
    data.rules = data.rules.concat(json.rules.map(rule => ({
      key: rule.key,
      htmlDesc: rule.htmlDesc,
      name: rule.name
    })));
  } while (nbResults === pageSize);

}

{
  const pageSize = 500;
  let page = 1;
  let nbResults;
  do {
    const res = request(
      "GET",
      `${sonarBaseURL}/api/issues/search?types=VULNERABILITY&componentKeys=${sonarComponent}&ps=${pageSize}&p=${page}&statuses=OPEN,CONFIRMED,REOPENED&s=STATUS&asc=no${leakPeriodFilter}`,
      cookies ? {
        headers: {
          'Cookie': cookies
        }
      } : undefined
    );
    page++;
    const json = JSON.parse(res.getBody());
    nbResults = json.issues.length;
    data.issues = data.issues.concat(json.issues.map(issue => {
      const rule = data.rules.find(rule => rule.key === issue.rule);
      const message = rule ? rule.name : "/";
      return {
        rule: issue.rule,
        severity: issue.severity,
        component: issue.component,
        description: message,
        message: issue.message
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