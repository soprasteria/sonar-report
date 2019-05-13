# sonar-report

## Install

You need to install [NodeJS](https://nodejs.org/en/) > 7

```bash
$ sudo npm install -g git+ssh://git@github.com/soprasteria/sonar-report.git
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
  --sonarcomponent="org.apache:tomcat:8.x" \
  --project="Apache Tomcat 8.x" \
  --application="tomcat" \
  --release="1.0.0" \
  --sinceleakperiod="false" > /tmp/sonar-report_tomcat8.html


# Open in browser
xdg-open /tmp/sonar-report
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
   

## Develop
Get the dependencies:

```bash
npm install
```
 
Run with the same command as §"Use" but use `node index.js` instead of `sonar-report`


