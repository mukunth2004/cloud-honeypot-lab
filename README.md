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
