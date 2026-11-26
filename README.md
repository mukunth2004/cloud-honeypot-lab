# Cloud honeypot with automated response

An SSH honeypot on AWS that logs attackers, detects bad behaviour in Elastic, and blocks the source address automatically.

## Architecture

```mermaid
flowchart LR
    ATT([Internet visitors])

    subgraph AWS["AWS (eu-north-1), built with Terraform"]
        NACL["Network ACL<br/>stateless, deny rules"]
        subgraph EC2["EC2 instance"]
            COW["Cowrie honeypot<br/>(Docker)"]
            FB["Filebeat"]
        end
        LAM["Lambda<br/>block-ip"]
        DDB[("DynamoDB<br/>block records")]
        EB["EventBridge<br/>every 5 min"]
    end

    ELK["Elastic Security<br/>(serverless)<br/>2 detection rules"]

    ATT -->|SSH| NACL --> COW
    COW -->|JSON logs| FB
    FB -->|HTTPS| ELK
    ELK -->|webhook + secret| LAM
    LAM -->|add deny rule| NACL
    LAM <-->|rule numbers, 2 h expiry| DDB
    EB -->|cleanup| LAM
```

## How it works

1. **Honeypot.** [Cowrie](https://github.com/cowrie/cowrie) runs in Docker on a small EC2 instance and pretends to be an SSH server. It accepts almost any login and records every command in a fake shell, but nothing a visitor does touches the real system. The image is pinned by digest, so the version cannot change silently.
2. **Log shipping.** Filebeat reads Cowrie's JSON log and sends it over HTTPS to an Elastic Security serverless project. Its API key is read from AWS Parameter Store at boot, so no secret is stored in the repo.
3. **Detection.** Two rules run in Elastic:
   - **Command burst:** 20 or more commands from one address within 5 minutes.
   - **Suspicious command:** a single command containing `nohup`, `chmod`, `wget` or `curl`, which is typical of installing malware.
4. **Response.** When a rule fires, Elastic calls a Lambda function over HTTPS. The Lambda checks a shared secret, then adds a deny rule for that address to the network ACL. DynamoDB hands out rule numbers (10 to 26) with conditional writes, so two simultaneous alerts cannot take the same number.
5. **Expiry.** Each block lasts 2 hours. A scheduled run every 5 minutes removes expired rules, so the ACL cannot fill up and block addresses forever.

Everything is defined in Terraform. Checkov scans it on every push through GitHub Actions.

## Results

Collected between 14 and 26 November 2026, with my own test addresses excluded.

| Measure | Value |
|---|---|
| Sessions | 969 |
| Distinct source addresses | 527 |
| Log events | 3,233 |
| Share of connections that ran a command (one automated client removed) | 5.1% |
| Real automated client blocked by the Lambda | 1 (confirmed in CloudTrail, expired after 2 h) |
| Delay from the 20th command to the block (5 controlled runs) | median 39.6 s, range 9.7 to 53.8 s |

![Sessions per day](docs/images/sessions-per-day.png)

Traffic was steady at about 60 to 100 sessions a day. The spike on 21 November was one address opening 87 sessions in about 95 seconds, which is the client the Lambda blocked.

![How far visitors got](docs/images/funnel-all-visitors.png)

Most connections never tried to log in. They are scanners.

![Most common commands](docs/images/common-commands.png)

Most commands test whether the shell is real, then fingerprint the machine.

Full write-up, including what the data does not show: [docs/analysis.md](docs/analysis.md).

## Security decisions

| Decision | Why |
|---|---|
| No SSH to the instance; admin access through SSM Session Manager | No inbound admin port to attack, and sessions are logged in AWS |
| IMDSv2 required, hop limit 1 | A process inside the Cowrie container cannot reach the instance's credentials |
| Least-privilege IAM, plus an explicit Deny on all SSM parameters except the Filebeat key | A negative test showed the managed `AmazonSSMManagedInstanceCore` policy could read other parameters, so I added the Deny and re-tested |
| Security group allows outbound only on 80, 443 and 53 | A compromised honeypot cannot easily connect out to other ports |
| Lambda Function URL with a shared secret checked by `hmac.compare_digest` | Only Elastic can trigger a block, and the check is constant-time |
| Terraform manages the base NACL rules and the Lambda manages the runtime deny rules as separate resources | A `terraform apply` does not delete blocks the Lambda has just added |
| Checkov scans the Terraform in GitHub Actions: 61 passed, 0 failed, 19 skipped | Every skip has a written reason in the code |
| Docker image pinned by digest | The honeypot version cannot change without a commit |
