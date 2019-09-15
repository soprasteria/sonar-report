# sonar-report

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=soprasteria_sonar-report&metric=alert_status)](https://sonarcloud.io/dashboard?id=soprasteria_sonar-report)
[![Build Status](https://travis-ci.org/soprasteria/sonar-report.svg?branch=master)](https://github.com/soprasteria/sonar-report)
[![Dependencies](https://david-dm.org/soprasteria/sonar-report/status.svg?path=client)](https://david-dm.org/soprasteria/sonar-report?path=client&view=list)
[![Dev Dependencies](https://david-dm.org/soprasteria/sonar-report/dev-status.svg?path=client)](https://david-dm.org/soprasteria/sonar-report?path=client&type=dev&view=list)

![tomcat screenshot example](https://github.com/soprasteria/sonar-report/raw/master/screenshots/tomcat1.png "tomcat screenshot example")

![tomcat screenshot example](https://github.com/soprasteria/sonar-report/raw/master/screenshots/tomcat2.png "tomcat screenshot example")

## Install

You need to install [NodeJS](https://nodejs.org/en/) > 7

```bash
$ npm install -g sonar-report
$ sonar-report --help
SYNOPSIS
    sonar-report [OPTION]...

...
```

## Use

```bash
# Generate report example
sonar-report \
  --sonarurl="https://sonarcloud.io" \
  --sonarcomponent="sopra-steria:soprasteria_sonar-report" \
  --project="Sonar Report" \
  --application="sonar-report" \
  --release="1.0.0" \
  --sinceleakperiod="false" \
  --allbugs="false" > /tmp/sonar-report_sonar-report.html


# Open in browser
xdg-open /tmp/sonar-report_sonar-report.html
```

The report is generated in `/tmp/sonar-report.html`

### sinceleakperiod

The `sinceleakperiod` parameter activates delta analysis. If `true`, sonar-report will only get the vulnerabilities that were added since a fixed date/version or for a number of days. For this it will:

- get `sonar.leak.period` value using sonar settings API.
- filter accordingly when getting the issues using the issues API.

When sinceleakperiod is activated, the report will include an additional `Reference period` field that holds the leak period configured in SonarQube.

More info:

- [Sonar documentation](https://docs.sonarqube.org/latest/user-guide/fixing-the-water-leak/ "leak period")
- In sonarQube, /settings : see leak period

### allbugs
- "false": only vulnerabilities are exported
- "true": all bugs are exported

### fixMissingRule
On some versions of sonar (found on 6.5), the `type` of issue and the `type` of the rule don't match (for example `VULNERABILITY` vs `CODE_SMELL` ). 

In this case, when `allbugs=false`, it's possible that the issue is extracted but not it's rule. What will happen is that the issue has `/` in the description (because the description is the name of the rule).

To circumvent this issue, the fixMissingRule will extract all rules without any filter on the `type`. 

Beware that, with this parameter activated, all the issues linked to the rules displayed may not be displayed. 

### noSecurityHotspot
Set this flag to true if using a sonarQube version that doesn't support security hotspots (<7.3?)

## Develop

Get the dependencies:

```bash
npm install
```

Run with the same command as [Use](#use) but use `node index.js` instead of `sonar-report`

## Troubleshooting

- The description is "/"

Set `fixMissingRule` to true

- Error "Value of parameter 'types' (SECURITY_HOTSPOT) must be one of: [CODE_SMELL, BUG, VULNERABILITY]"}]}

Your version of sonarQube doesn't support security hotspots. Set `noSecurityHotspot` to true.
