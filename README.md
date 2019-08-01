# sonar-report

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=com.soprasteria.cdk%3Asonar-report&metric=alert_status)](https://sonarcloud.io/dashboard?id=com.soprasteria.cdk%3Asonar-report)
[![Build Status](https://travis-ci.org/soprasteria/sonar-report.svg?branch=master)](https://github.com/soprasteria/sonar-report)

![jhipster screenshot example](https://github.com/soprasteria/sonar-report/raw/master/screenshots/jhipster1.png "jhipster screenshot example")

![jhipster screenshot example](https://github.com/soprasteria/sonar-report/raw/master/screenshots/jhipster2.png "jhipster screenshot example")

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
  --sonarcomponent="com.soprasteria:sonar-report" \
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
- false: only vulnerabilities are exported
- false: all bugs are exported

## Develop

Get the dependencies:

```bash
npm install
```

Run with the same command as [Use](#use) but use `node index.js` instead of `sonar-report`
