# Setup guide

The setup guide takes a workspace from empty to a first working result: a monitored website, tracked assets, an import, working alerts, or a Certificate Management (CertOps) setup for Linux, Windows or Kubernetes. It is optional, you can leave it at any time, and everything it creates stays in your workspace.

The guide never keeps its own record of what is done when the server can tell. A step is marked done from what the server reports (assets, monitors, contact groups, agents, controllers, jobs). Reloading the page, switching device or doing the work somewhere else in the app keeps the step list correct.

## Open the guide

- **Empty workspace.** The first time you open a workspace with no assets and no monitors, a one-time prompt offers the guide. Once the prompt has been shown, a setup banner on the dashboard keeps the way back until you finish or hide the guide.
- **Welcome window.** The first-run welcome window has a **Set up my environment** action.
- **Account preferences.** The **Setup guide** row has **Open setup guide** and **Start over**. **Start over** clears the guide's progress only. Assets, agents, certificates and anything else it created are kept.
- **Certificate Management.** The **Settings** tab has a **CertOps quickstart** card (see [Restart or continue the CertOps setup](#restart-or-continue-the-certops-setup)). While a workspace has no agents, no managed certificates and no AD CS issuers, the Certificate Management pages also show a setup banner to people who can manage CertOps.

Viewers do not see these invitations. Most steps need the workspace manager or administrator role. The Microsoft CA goal needs a workspace administrator, and SMTP setup needs a system administrator. A person without the role sees which role to ask, for example "Ask a workspace administrator to complete this step."

## Your setup and progress

Beside each step the guide shows a panel called **Your setup**. It has:

- A line such as **3 of 8 steps finished** and a progress bar. The count includes the first step, **What do you want to do first?**, once you have chosen a goal.
- The list of steps for your goal, each with a badge: **Done**, **Now**, **Next** or **Skipped**. You can open any step that is not **Next**. Steps you have not reached yet cannot be opened.
- **Change what I am setting up**, which returns to the goal screen. Anything already created is kept.

Progress is saved to your account, so you can leave at any time and continue on another device. On narrow screens the step list collapses into a compact list.

There are no Back buttons on the individual steps. The step list is the way to move between steps.

## Back to where I was

If you open the goal screen from the step list while another step is in progress, the goal screen shows one **Back to where I was** button next to **Continue**. It returns you to the step you left. The button is not shown when you reach the goal screen at the start.

## Finished steps stay open until you press Continue

Some steps finish by themselves while you watch: an agent checks in, a dry run completes, the first certificate is issued or a controller reports, an AD CS issuer and profile are created, a Vault rollout finishes, or you tick a contact group. The guide keeps the finished step on screen with its result, updates the step count, and moves on only when you press **Continue**. Reopening a step that was already finished when you arrived does not hold it.

## Goals

The goal screen groups goals by area. Each shows the time it needs and what it requires.

| Area                   | Goal                                              | What it sets up                                                                                          |
| ---------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Track assets           | Monitor a website certificate                     | Monitors one or several websites, then asks who gets alerted.                                            |
| Track assets           | Track an API key, secret or license               | Adds up to 25 assets by hand, then asks who gets alerted.                                                |
| Track assets           | Import many assets from a file                    | Opens the regular import dialog on **File**.                                                             |
| Track assets           | Import from GitHub, Vault, AWS or another service | Opens the regular import dialog with the service tiles.                                                  |
| Alerts                 | Set up alert notifications                        | Recipients, thresholds, email delivery and a test email.                                                 |
| Certificate management | Discover certificates on my servers               | An agent (Linux or Windows) or the Kubernetes controller reports certificates without changing anything. |
| Certificate management | Issue and renew certificates automatically        | An agent requests, installs and renews certificates over ACME.                                           |
| Certificate management | Issue certificates from my Microsoft CA (AD CS)   | A domain-joined Windows agent enrolls certificates from your private CA.                                 |
| Certificate management | Share one certificate across servers with Vault   | Publishes a certificate to your Vault and deploys it to several hosts.                                   |

Goals that are not available to you are hidden or shown with the reason. Progress from one CertOps goal never marks another as done, and a saved configuration for one objective survives switching to another. Changing the platform on **Where will the certificates live?** drops the earlier platform's step marks and opens the first step that is not really done.

## Websites to monitor

The website goal adds several websites in one batch of up to 50. You choose the check interval, whether to alert when a site is down, and how many failed checks in a row count as down.

### Subdomain discovery

You can optionally find a domain's public subdomains first. The lookup uses public sources, so the domain name is sent to public lookup services, and it can take a minute or two.

- Found websites are listed 50 per page. A filter box narrows the list by name, and **Select all** picks every match across pages, as many as still fit in the batch.
- If the list was cut at the maximum, the guide says so: "The list was cut at N websites, so some are not shown."
- If only some sources answered, the guide says "Some sources did not answer, so there may be more." If the lookup ran out of time it says "The search ran out of time before every source answered, so there may be more."
- Lookups are rate limited to one per minute for each user and workspace. A second lookup inside that minute answers "Too many searches. Try again in about Ns." Change the limit with `DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_MAX` and `DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_WINDOW_MS`.
- Discovery needs the `subfinder` tool on the API host. If it is missing, the guide says "Website discovery is not available on this server. Add websites by address instead." Set `SUBFINDER_BIN` to the full path when `subfinder` is not on the `PATH` of the API.

## Imports

The two import goals open the regular **Import tokens** dialog, the same one the dashboard uses.

- **Import many assets from a file** opens on **File**. Use it for CSV, spreadsheet, JSON or YAML inventories.
- **Import from GitHub, Vault, AWS or another service** shows the service tiles only: GitHub, GitLab, HashiCorp Vault, AWS, Azure Key Vault, Microsoft Entra ID and Google Cloud. (The Entra ID tile used to be labelled Azure AD.) File and Certificate (PEM) are not offered in this goal.
- A file may be at most 5 MB and 5000 rows. A larger file is refused before upload with a plain message, for example "This file is 6.2 MB. The limit is 5 MB. Split it into smaller files and import them one at a time." or "This file has 6000 rows. The limit is 5000 rows per file. Split it into smaller files and import them one at a time."
- When scheduled sync is available and you turn it on, the dialog shows one line, **Alerts for synced items go to: `<group>`**, with a **Change** link. The group applies to assets a later sync creates. Assets that exist already keep the group they have, and a deleted group falls back to the workspace default.

These two goals end after a successful import. The closing card links to the asset inventory and to Alert Preferences. They do not include the alerts or verify steps.

## Choose who gets alerted

- The step attaches contact groups to what the guide created in this session. Tick the groups that should receive alerts. Several groups are usual, so ticking or unticking never moves you on. Press **Continue**.
- For websites and assets the step is done when each one carries a group that reaches someone. For the other goals you confirm with **Use these groups**.
- Groups can be created, edited and deleted in the step. The workspace default group is shown separately. Deleting a group never changes the default.
- **Skip for now** leaves the step as **Skipped**. Reopen it from the step list.

## Install the agent

The Linux and Windows goals show the install steps in order. The page is for one platform at a time: it prints the package download with its checksum, the paths for the system, the configuration to merge, and the install command.

- **Bootstrap token.** Step 3 holds the **Create bootstrap token** button. The token is created inside the step and replaces the marked `<bootstrap token>` slot in the install command. It is shown once and expires in 24 hours. If you lose it or it expires, press **Create another token**. A reinstall with different options needs a new token.
- **What satisfies the step.** Any live agent on the right operating system that has the goal's command profile and every capability the goal needs satisfies the step, in any order. Other agents in the workspace do not block it and are not shown as its agent. A live Linux agent that lacks capabilities is named together with what it lacks and where to install. A missing capability blocks the step and names the agent build that declares it and the upgrade step.
- **ACME goals on Linux** need `certbot` on the issuing server. The guide says so before the install command.
- **Microsoft CA goal.** Install the agent on a domain-joined Windows Server member, not on a domain controller. See [Microsoft AD CS](certops/agent/adcs.md).
- The guide warns when the CertOps worker looks stopped, for example when an enrollment is overdue for polling or the outbox has a backlog. The worker is a requirement of every CertOps goal.

The install runbooks cover the same commands in full: [Linux](certops/agent/install-linux.md) and [Windows](certops/agent/install-windows.md).

## Kubernetes

For Kubernetes the discover goal installs the cert-manager controller instead of an agent, and it has 6 steps in the step list. The agent configuration and execution safety steps are left out because they describe an agent host.

The install step is titled **Install the Kubernetes controller**. In observe mode the controller only reads cert-manager resources. The step asks you to:

1. Choose a cluster id.
2. Create a machine token in Certificate Management under **Settings**, with the scope `certops:observations:write` and that same cluster id (the token is bound to it), and store it in the cluster with the printed command, which reads the token from standard input.
3. Save the printed Helm values and upgrade your TokenTimer Helm release with them. If the cluster does not run TokenTimer, add the extra lines the step prints so that only the controller is installed. cert-manager must already be installed.

**Controller status** shows **Waiting for the controller** and turns to **Reporting** when the controller sends its first cert-manager `Certificate`, so the cluster needs at least one.

## Job approval

The guide asks for approval only when it matters:

- It mentions approval when the workspace **Job approval** setting is on (Certificate Management, **Settings**). A job then waits until a workspace manager other than the person who created it approves it in Certificate Management, **Jobs**.
- It shows an approval prompt when a job it started is actually pending approval, read from the job status.
- With the setting off, jobs start right away. The steps show a one-line note with a link to the CertOps settings, and a Vault publish job carries no per-job approval flag.
- A Vault rollout always needs approval from a different user, whatever the setting says.

## Closing card and next steps

The last step, **Check that it is working**, checks the result against the server. The closing card then states the outcome. For the Microsoft CA and Vault goals it says that the setup is ready but not verified until the first enrollment or rollout has happened.

Under the outcome the card lists optional next steps as short cards. Each has an icon, a title, a sentence and a link to the right page, for example opening the inventory, tuning alert thresholds, opening Certificates, Agents or Renewals, switching to a real domain and the production CA, or confirming email delivery.

## Restart or continue the CertOps setup

The **CertOps quickstart** card on the Certificate Management **Settings** tab is a permanent way back. The button reads **Continue the CertOps quickstart** when a CertOps goal is in progress, and **Start the CertOps quickstart** otherwise. After a finished or dismissed guide it starts clean. Whatever the guide created earlier (assets, agents, certificates) is kept, so you can run it again, for example to add another server. People who cannot manage CertOps do not see the card.

## Deployment requirements

- **Email.** A system administrator sets up SMTP in System Settings or with environment variables, see [Configuration basics](CONFIGURATION_BASICS.md). Others see "Ask a system administrator to configure SMTP."
- **Certificate Management** must be enabled on the deployment. Otherwise the goals show "Certificate management is disabled on this deployment. An operator must enable it."
- **Discovery** needs `subfinder` on the API host. The official API image includes it.
