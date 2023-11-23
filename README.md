# sonarqube-report

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=soprasteria_sonar-report&metric=alert_status)](https://sonarcloud.io/dashboard?id=soprasteria_sonar-report)
[![Build Status](https://travis-ci.org/soprasteria/sonarqube-report.svg?branch=master)](https://github.com/soprasteria/sonarqube-report)

![screenshot example](screenshots/immagine(1).png "screenshot example")

![screenshot example](screenshots/immagine(2).png "screenshot example")

## Install

Compatible with node 14+

```bash
$ npm install -g sonarqube-report
```

## Use

- See all options with:

```bash
$ sonarqube-report -h
Usage: sonarqube-report [options]

Generate a vulnerability report from a SonarQube instance.
```

- Environment:

  - http_proxy : the proxy to use to reach the sonarqube instance (`http://<host>:<port>`)
  - NODE_EXTRA_CA_CERTS
    - the custom certificate authority to trust (troubleshoots `Unable to verify the first certificate`)
    - the variable holds a file name that contains the certificate in pem format (root CA or full trust chain)

- Example:

```bash
# Generate report example
sonarqube-report \
  --project="my-project" \
  --application="my-application" \
  --release="1.0.1"  \
  --coverage \
  --link-issues  \
  --sonarorganization="invitalia" \
  --quality-gate-status  \
  --sonarurl="https://sonarqube.invitalia.it/" \
  --sonarcomponent="my-component" \
  --allbugs \
  --only-detected-rules  \
  --sonartoken="$TOKEN"  \
  --branch="main"  \
  --output="./report.html"
```

## Migrate to v3

- Compared the flags, most of them switched from snake-case to keba-case
- there is a new flag to ouput the report in a specific folder `--output`, it allows to generate a summary report that can be viewed in the CI:

  ```txt
  Report Generated On Wed Aug 24 2022

  Project Name: Sonar Report
  Application: sonarqube-report
  Release: 1.0.0
  Delta analysis: No

  Summary of the Detected Vulnerabilities

  Severity: BLOCKER
  Number of Issues: 0

  Severity: CRITICAL
  Number of Issues: 0

  Severity: MAJOR
  Number of Issues: 0

  Severity: MINOR
  Number of Issues: 0
  ```

## Some parameters explained

### --since-leak-period

The `--since-leak-period` parameter activates delta analysis. If `true`, sonarqube-report will only get the vulnerabilities that were added since a fixed date/version or for a number of days. For this it will:

- get `sonar.leak.period` value using sonar settings API.
- filter accordingly when getting the issues using the issues API.

When sinceleakperiod is activated, the report will include an additional `Reference period` field that holds the leak period configured in SonarQube.

More info:

- [Sonar documentation](https://docs.sonarqube.org/latest/user-guide/fixing-the-water-leak/ "leak period")
- In sonarQube, /settings : see leak period

### --allbugs

- "false": only vulnerabilities are exported
- "true": all bugs are exported

### --fix-missing-rule

On some versions of sonar (found on 6.5), the `type` of issue and the `type` of the rule don't match (for example `VULNERABILITY` vs `CODE_SMELL` ).

In this case, when `allbugs=false`, it's possible that the issue is extracted but not it's rule. What will happen is that the issue has `/` in the description (because the description is the name of the rule).

To circumvent this issue, the fixMissingRule will extract all rules without any filter on the `type`.

Beware that, with this parameter activated, all the issues linked to the rules displayed may not be displayed.

### --no-security-hotspot

sonarqube-report will try to find how your sonarqube instance is working with hotspots depending on the running version. However in last resort, you can use the `--no-security-hotspot` flag in order to deactivate the hotspots processing.

**Note that you may miss out on some vulnerabilities when using this option if your sonarqube instance does support hotspots.**

### --only-detected-rules

Enumerate only activated rules, referenced by detected vulnerabilities.


General information about security hotspots: https://docs.sonarqube.org/latest/user-guide/security-hotspots/

Here's a brief history of sonarqube dealing with hotspots.

- version < 7.3
  - hotspots don't exist
- 7.3 <= version < 7.8:
  - hotspots are stored in the /issues endpoint
  - issue status doesn't include TO_REVIEW, IN_REVIEW yet
  - issues type includes SECURITY_HOTSPOT
  - rules type includes SECURITY_HOTSPOT for now on
- 7.8 <= version < 8.2
  - hotspots are stored in the /issues endpoint
  - issue status includes TO_REVIEW, IN_REVIEW
  - issues type includes SECURITY_HOTSPOT
- version >= 8.2
  - hotspots are in a dedicated endpoint /hotspots
  - issues status don't include anymore TO_REVIEW, IN_REVIEW
  - issues type don't include anymore SECURITY_HOTSPOT

A few notes:

- this behavior was verified using the embedded web_api documentation from dockerhub community distributions
- Versions 7.2 and 7.3 couldn't be verified as they are not present on dockerhub (and sonarqube doesn't seem to be publishing the API documentation per version)
- some implementations may not work as expected: for example sonarcloud v8.0 doesn't know about hotspots. When using sonarcloud v8.0 please use the `--no-security-hotspot` flag

To verify how your instance deals with hotspots, check:

- ${sonarBaseURL}/api/system/status
- ${sonarBaseURL}/web_api/api/issues/search (check Possible values of parameters `statuses`, `types`)
- ${sonarBaseURL}/web_api/api/rules/search (check Possible values of parameter `types`)
- ${sonarBaseURL}/web_api/api/hotspots

## Develop

Get the dependencies:

```bash
npm install
```

Run with the same command as [Use](#use) but use `node cli.js` instead of `sonarqube-report`

## Troubleshooting

- The description is "/"

Set `--fix-missing-rule` to true

- Error `Value of parameter 'types' (SECURITY_HOTSPOT) must be one of: [CODE_SMELL, BUG, VULNERABILITY]"}]}`
- or: `Error while getting issues :  - Response code 400 (Bad Request) - 400 - Bad Request - {"errors":[{"msg":"Value of parameter \u0027statuses\u0027 (TO_REVIEW) must be one of: [OPEN, CONFIRMED, REOPENED, RESOLVED, CLOSED]"}]}`

Your version of sonarQube doesn't support security hotspots. Set `--no-security-hotspot` to true. (more info check [--no-security-hotspot](#no-security-hotspot) description above)

- `{"errors":[{"msg":"Can return only the first 10000 results. 10500th result asked."}]}`

This is a limitation in sonarQube API. There is no way around it to date apart from adding limiting filters

Try removing `--allbugs` or tune the query in index.js (see /web_api/api/issues under your sonarQube instance)

See also this discussion <https://community.sonarsource.com/t/cannot-get-more-than-10000-results-through-web-api/3662/4>
